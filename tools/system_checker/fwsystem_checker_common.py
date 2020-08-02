#! /usr/bin/python

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2019  flexiWAN Ltd.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
################################################################################

import glob
import json
import os
import psutil
import re
import ruamel.yaml
import subprocess
import sys
import uuid
import yaml
import shutil

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , 'common')
sys.path.append(common_tools)
from fw_vpp_startupconf import FwStartupConf, L, T

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)
import fwglobals
import fwutils
import fwnetplan

class Checker:
    """This is Checker class representation.

    :param debug:          Debug mode.

    """
    def __init__(self, debug=False):
        """Constructor method
        """
        fwglobals.initialize()

        self.CFG_VPP_CONF_FILE      = fwglobals.g.VPP_CONFIG_FILE
        self.CFG_FWAGENT_CONF_FILE  = fwglobals.g.FWAGENT_CONF_FILE
        self.debug                  = debug   # Don't use fwglobals.g.cfg.DEBUG to prevent temporary checker files even DEBUG is enabled globally
        self.wan_interfaces         = None
        self.nameservers            = None
        self.detected_nics          = None
        self.supported_nics         = None
        self.fw_ac_db               = FwStartupConf()
        self.vpp_configuration      = L(self.fw_ac_db.load(self.CFG_VPP_CONF_FILE))
        self.vpp_config_modified    = False
        self.update_grub            = False

        supported_nics_filename = os.path.join(os.path.dirname(os.path.realpath(__file__)) , 'dpdk_supported_nics.json')
        with open(supported_nics_filename, 'r') as f:
            self.supported_nics = json.load(f)

    def save_config (self):
        if self.vpp_config_modified:
            self.fw_ac_db.dump(self.vpp_configuration, self.CFG_VPP_CONF_FILE)
            self.update_grub_file()
        shutil.copyfile(fwglobals.g.VPP_CONFIG_FILE, fwglobals.g.VPP_CONFIG_FILE_BACKUP)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        if self.vpp_config_modified:
            self.fw_ac_db.dump(self.vpp_configuration, self.CFG_VPP_CONF_FILE)

    def hard_check_sse42(self, supported):
        """Check SSE 4.2 support.

        :param supported:       Unused.

        :returns: 'True' if supported and 'False' otherwise.
        """
        try:
            out = subprocess.check_output('cat /proc/cpuinfo | grep sse4_2', shell=True).strip()
        except subprocess.CalledProcessError:
            return False
        return True

    def hard_check_ram(self, gb):
        """Check RAM requirements.

        :param gb:       Minimum RAM size in GB.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        if psutil.virtual_memory().total < gb * pow(1000, 3):  # 1024^3 might be too strict if some RAM is pre-allocated for VM
            return False
        return True

    def hard_check_cpu_number(self, num_cores):
        """Check CPU requirements.

        :param num_cores:       Minimum CPU cores number.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        if psutil.cpu_count() < num_cores:
            return False
        return True

    def hard_check_nic_number(self, num_nics):
        """Check NICs number.

        :param num_nics:       Minimum NICs number.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        try:
            # NETWORK_BASE_CLASS = "02", so look for 'Class:  02XX'
            out = subprocess.check_output("lspci -Dvmmn | grep -cE 'Class:[[:space:]]+02'", shell=True).strip()
            if int(out) < num_nics:
                return False
        except subprocess.CalledProcessError:
            return False
        return True

    def hard_check_wan_connectivity(self, supported):
        """Check WAN connectivity.

        :param supported:       Unused.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        self.wan_interfaces = []
        interfaces = [ str(iface) for iface in psutil.net_if_addrs() if str(iface) != "lo" ]
        for iface in interfaces:
            print "\rcheck WAN connectivity on %s" % iface,
            sys.stdout.flush()      # Need this as tail ',' remove the 'newline' in print(), so the print is not flushed immediately
            ret = os.system("ping -c 1 -W 5 -I %s 8.8.8.8 > /dev/null 2>&1" % iface)
            if ret == 0:
                self.wan_interfaces.append(str(iface))
        print "\r                                                         \r",  # Clean the line before it is overwrote by next print
        if len(self.wan_interfaces) == 0:
            return False
        return True

    def hard_check_kernel_io_modules(self, supported):
        """Check kernel IP modules presence.

        :param supported:       Unused.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        modules = [
            # 'uio_pci_generic',  # it is not supported on Amazon, and it is not required as we use 'vfio-pci'
            'vfio-pci'
        ]
        succeeded = True
        for mod in modules:
            ret = os.system('modinfo %s > /dev/null 2>&1' %  mod)
            if ret:
                print(mod + ' not found')
                succeeded = False
        return succeeded

    def hard_check_nic_drivers(self, supported):
        """Check NIC drivers.

        :param supported:       Unused.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        # Firstly gather info about installed network cards
        if self.detected_nics is None:
            self.detected_nics = {}
            try:
                out = subprocess.check_output("lspci -vnn", shell=True).strip().split('\n\n')
                # 00:03.0 Ethernet controller [0200]: Intel Corporation 82540EM Gigabit Ethernet Controller [8086:100e] (rev 02)
                #     Subsystem: Intel Corporation PRO/1000 MT Desktop Adapter [8086:001e]
                #     Flags: bus master, 66MHz, medium devsel, latency 64, IRQ 19
                #     Memory at f1200000 (32-bit, non-prefetchable) [size=128K]
                #     I/O ports at d020 [size=8]
                #     Capabilities: [dc] Power Management version 2
                #     Capabilities: [e4] PCI-X non-bridge device
                #     Kernel driver in use: e1000
                #     Kernel modules: e1000
                for device in out:
                    params = device.split('\n', 1)
                    match = re.search('\[02..\]:', params[0])   # [02XX] stands for Network Base Class
                    if not match:
                        continue
                    match = re.search('([^ ]+) .*\[02..\]: ([^ ]+)', params[0])
                    if not match:
                        print("device: %s" % (str(device)))
                        print("params[0]: %s" % (str(params[0])))
                        raise Exception("not supported format of 'lspci -vnn' output")
                    pci          = match.group(1)
                    manufacturer = match.group(2)
                    driver       = device.split('Kernel driver in use: ', 1)[1].split('\n')[0]

                    # Don't take manufacturer into account, as it's name might differ a little bit,
                    # e.g. Amazon in supported_nics vs Amazon.com in 'lspci -vnn' on AWS Ubuntu
                    ##supported    = True if manufacturer.lower() in self.supported_nics and \
                    ##               driver in self.supported_nics[manufacturer.lower()] else False
                    ### Take care of virtualization
                    ##if not supported and driver in self.supported_nics['paravirtualization']:
                    ##    supported = True
                    supported = False
                    for m in self.supported_nics:
                        if driver.lower() in self.supported_nics[m]:
                            supported = True
                    self.detected_nics[pci] = {
                        'manufacturer' : manufacturer,
                        'driver' : driver,
                        'supported' : supported }
            except Exception as e:
                print(str(e))
                return False

        # Now go over found network cards and ensure that they are supported
        succeeded = True
        for pci in self.detected_nics:
            device = self.detected_nics[pci]
            if not device['supported']:
                print('%s %s driver is not supported' % (device['manufacturer'], device['driver']))
                succeeded = False
        return succeeded

    def soft_check_uuid(self, fix=False, silently=False, prompt=''):
        """Check if UUID is present in system.

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        uuid_filename = '/sys/class/dmi/id/product_uuid'
        try:
            found_uuid = subprocess.check_output(['cat', uuid_filename]).decode().split('\n')[0].strip()
            if not found_uuid:
                raise Exception("failed to read %s" % uuid_filename)
            # Ensure proper syntax of retrieved UUID
            try:
                uuid_obj = uuid.UUID(found_uuid)
                if uuid_obj.variant==uuid.RFC_4122 and not uuid_obj.version:
                    raise Exception("failed to deduce version of found UUID according RFC4122: %s" % found_uuid)
            except ValueError:
                raise Exception("found UUID '%s' doesn't comply to RFC" % found_uuid)
            return True

        except Exception as e:
            print(prompt + str(e))

            # Check if fwagent configuration file has the simulated uuid
            with open(self.CFG_FWAGENT_CONF_FILE, 'r') as f:
                conf = yaml.load(f, Loader=yaml.SafeLoader)
                if conf.get('agent') and conf['agent'].get('uuid'):
                    return True

            print(prompt + "UUID was found neither in system nor in %s" % self.CFG_FWAGENT_CONF_FILE)
            if not fix:
                return False

            # Fix UUID: generate it and save into fwagent configuration file.
            # We use ruamel.yaml and not yaml to preserve comments.
            new_uuid = str(uuid.uuid1()).upper()
            if not silently:
                choice = raw_input(prompt + "use %s ? [Y/n]: " % new_uuid)
                if choice != 'y' and choice != 'Y' and choice != '':
                    return False
            f = open(self.CFG_FWAGENT_CONF_FILE, 'r')
            ruamel_yaml = ruamel.yaml.YAML()
            conf = ruamel_yaml.load(f)
            conf['agent']['uuid'] = new_uuid
            f.close()
            f = open(self.CFG_FWAGENT_CONF_FILE, 'w')
            ruamel_yaml.dump(conf, f)
            f.close()
            return True

    def hard_check_default_route_connectivity(self, fix=False, silently=False, prompt=''):
        """Check route connectivity.

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        try:
            # If self.wan_interfaces was not filled yet (by hard_soft_checker), fill it
            if self.wan_interfaces is None:
                self.hard_check_wan_connectivity(True)

            # Find all default routes and ensure that configured interface has WAN connectivity
            default_routes = subprocess.check_output('ip route | grep default', shell=True).strip().split('\n')
            if len(default_routes) == 0:
                print(prompt + "no default route was found")
                return False
            for route in default_routes:
                # The 'route' should be in 'default via 192.168.1.1 dev enp0s3 proto static' format
                # Extracts the interface name from this line and ensure that it presents in self.wan_interfaces.
                iface_name = route.split(' ')[4]
                if iface_name in self.wan_interfaces:
                    return True
            print(prompt + "default route has no WAN connectivity")
            return False
        except Exception as e:
            print(prompt + str(e))
            return False

    def soft_check_default_route(self, fix=False, silently=False, prompt=''):
        """Check if default route is present.

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        try:
            # Find all default routes and ensure that there is exactly one default route
            default_routes = subprocess.check_output('ip route | grep default', shell=True).strip().split('\n')
            if len(default_routes) == 0:
                raise Exception("no default route was found")
            return True
        except Exception as e:
            print(prompt + str(e))
            if not fix:
                return False
            else:
                if silently:
                    return False
                while True:
                    ip = raw_input(prompt + "please enter GW address, e.g. 192.168.1.1: ")
                    try:
                        out = subprocess.check_output('ip route add default via %s' % ip, shell=True).strip()
                        return True
                    except Exception as e:
                        print(prompt + str(e))
                        while True:
                            choice = raw_input(prompt + "repeat? [Y/n]: ")
                            if choice == 'y' or choice == 'Y' or choice == '':
                                break
                            elif choice == 'n' or choice == 'N':
                                return False

    def _get_duplicate_metric(self):
        output = subprocess.check_output('ip route show default', shell=True).strip()
        routes = output.splitlines()

        metrics = {}
        for route in routes:
            dev = route.split('dev ')[1].split(' ')[0]
            rip = route.split('via ')[1].split(' ')[0]
            parts = route.split('metric ')
            metric = 0
            if len(parts) > 1:
                metric = int(parts[1])
            if metric in metrics:
                metrics[metric].append([dev,rip])
            else:
                metrics[metric] = [[dev,rip]]

        for metric, gws in metrics.items():
            if len(gws) > 1:
                return metric, metrics

        return None, None

    def _get_gateways(self):
        output = subprocess.check_output('ip route show default', shell=True).strip()
        routes = output.splitlines()

        gws = []
        for route in routes:
            rip = route.split('via ')[1].split(' ')[0]
            gws.append(rip)

        return gws

    def _add_netplan_interface(self, fname, dev, metric):
        print("%s is assigned metric %u" % (dev, metric))
        with open(fname, 'r') as stream:
            config = yaml.safe_load(stream)
            network = config['network']

        ethernets = network['ethernets']
        if dev in ethernets:
            section = ethernets[dev]
            if 'dhcp4' in section and section['dhcp4'] == True:
                section['dhcp4-overrides'] = {'route-metric': metric}
            else:
                def_route_existed = False
                if 'routes' in section:
                    routes = section['routes']
                    for route in routes:
                        if route['to'] == '0.0.0.0/0':
                            route['metric'] = metric
                            def_route_existed = True
                if not def_route_existed and 'gateway4' in section:
                    section['routes'] = [{'to': '0.0.0.0/0',
                                          'via': section['gateway4'],
                                          'metric': metric}]
                    del section['gateway4']

        with open(fname, 'w') as stream:
            yaml.safe_dump(config, stream)

    def _fix_duplicate_metric(self, primary_gw):
        metric, metrics = self._get_duplicate_metric()
        if metric is None:
            return True

        files = fwnetplan.get_netplan_filenames()
        metric = 100
        for fname, devices in files.items():
            os.system('cp %s %s.fworig' % (fname, fname))
            fname_baseline = fname.replace('yaml', 'baseline.yaml')
            os.system('mv %s %s' % (fname, fname_baseline))

            for dev in devices:
                ifname = dev.get('ifname')
                gateway = dev.get('gateway')
                if gateway is None:
                    continue
                if primary_gw is not None and gateway == primary_gw:
                    self._add_netplan_interface(fname_baseline, ifname, 0)
                else:
                    self._add_netplan_interface(fname_baseline, ifname, metric)
                    metric += 100

        subprocess.check_output('sudo netplan apply', shell=True)

        return True

    def soft_check_default_routes_metric(self, fix=False, silently=False, prompt=''):
        """Check if default routes have duplicate metrics.

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        try:
            # Find all default routes and ensure that there are no duplicate metrics
            metric, metrics = self._get_duplicate_metric()
            if metric is not None:
                raise Exception("Multiple default routes with the same metric %u" % metric)
            return True
        except Exception as e:
            print(prompt + str(e))
            if not fix:
                return False
            else:
                if silently:
                    gws = self._get_gateways()
                    return self._fix_duplicate_metric(gws[0])
                while True:
                    try:
                        print("\nGateways to choose from:")
                        gws = self._get_gateways()
                        id = 1
                        for gw in gws:
                            print("         %u  - %s" % (id, gw))
                            id += 1
                        id = int(raw_input(prompt + "please choose the gw number: "))
                        if id > len(gws):
                            print("Wrong number chosen!")
                            return False
                        return self._fix_duplicate_metric(gws[id-1])
                    except Exception as e:
                        print(prompt + str(e))
                        while True:
                            choice = raw_input(prompt + "repeat? [Y/n]: ")
                            if choice == 'y' or choice == 'Y' or choice == '':
                                break
                            elif choice == 'n' or choice == 'N':
                                return False


    def soft_check_hostname_syntax(self, fix=False, silently=False, prompt=None):
        """Check hostname syntax.

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        # Ensure the syntax of hostname.
        # We permit following symbols to keep MGMT robust: /^[a-zA-Z0-9-_.]{1,253}$/
        # Note standard requires all small letters, but Amazon uses capital letters too,
        # so we enable them.
        # ===========================================================================
        pattern = '^[a-zA-Z0-9\-_.]{1,253}$'
        try:
            hostname = subprocess.check_output(['hostname']).decode().split('\n')[0].strip()
            if not hostname:
                raise Exception("empty hostname was retrieved by 'hostname'")
            if not re.match(pattern, hostname):
                raise Exception("hostname '%s' does not comply standard" % hostname)
            result = True
        except Exception as e:
            print(prompt + str(e))
            hostname = ''
            result = False

        if not fix or silently:
            return result

        # Get new hostname from user
        while True:
            new_hostname = raw_input(prompt + "enter hostname: ")
            if re.match(pattern, new_hostname):
                break
            print(prompt + "hostname '%s' does not comply standard (%s)" % (new_hostname, pattern))

        # Write it into /etc/hostname
        hostname_filename = '/etc/hostname'
        ret = os.system('printf "%s\n" > %s' % (new_hostname, hostname_filename))
        if ret != 0:
            print(prompt + "failed to write '%s' into %s" % (new_hostname, hostname_filename))
            return False

        # On Ubuntu 18.04 server we should ensure 'preserve_hostname: true'
        # in '/etc/cloud/cloud.cfg', so change in /etc/hostname will survive reboot.
        cloud_cfg_filename = '/etc/cloud/cloud.cfg'
        if os.path.isfile(cloud_cfg_filename):
            ret = os.system('sed -i -E "s/(^[ ]*)preserve_hostname:.*/\\1preserve_hostname: true/" %s' % cloud_cfg_filename)
            if ret != 0:
                print(prompt + 'failed to modify %s' % cloud_cfg_filename)
                return False

        print(prompt + "please reboot upon configuration completion")
        return True


    def soft_check_hostname_in_hosts(self, fix=False, silently=False, prompt=None):
        """Check if hostname is present in /etc/hosts.

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        # Ensure that hostname appears in /etc/hosts with 127.0.0.1 and ::1
        hosts_file = '/etc/hosts'

        try:
            hostname = subprocess.check_output(['hostname']).decode().split('\n')[0].strip()
            if not hostname:
                raise Exception("empty hostname was retrieved by 'hostname'")
        except Exception as e:
            print(prompt + str(e))
            return False

        ret_ipv4 = os.system("grep --perl-regex '^[0-9.]+[\t ]+.*%s' %s > /dev/null 2>&1" % (hostname, hosts_file))
        ret_ipv6 = os.system("grep --perl-regex '^[a-fA-F0-9:]+[\t ]+.*%s' %s > /dev/null 2>&1" % (hostname, hosts_file))
        if ret_ipv4 == 0 :  # and  ret_ipv6 == 0:  # Enforce IPv4 and relax IPv6
            return True

        if not fix:
            print(prompt + "hostname '%s' not found in %s" % (hostname, hosts_file))
            return False

        def _add_record(address):
            try:
                out = subprocess.check_output("grep '%s' %s" % (address, hosts_file), shell=True).strip().split('\n')[0]
                if not out:
                    raise Exception
                # At this point we have 127.0.0.1 line, just go and add the hostname to it
                record = out + '\t' + hostname
                ret = os.system('sed -i -E "s/%s/%s/" %s' % (out, record, hosts_file))
                if ret != 0:
                    print(prompt + "failed to add '%s  %s' to %s" % (address, hostname, hosts_file))
                    return False
            except Exception as e:
                # At this point we have no 127.0.0.1 line, just go and add new record to the file
                ret = os.system('printf "%s\t%s\n" >> %s' % (address, hostname, hosts_file))
                if ret != 0:
                    print(prompt + "failed to add '%s  %s' to %s" % (address, hostname, hosts_file))
                    return False
            return True

        if ret_ipv4 != 0:
            success = _add_record('127.0.0.1')
            if not success:
                return False
        if ret_ipv6 != 0:
            success = _add_record('::1')
            if not success:
                return False
        return True

    def soft_check_disable_transparent_hugepages(self, fix=False, silently=False, prompt=None):
        """Check if transparent hugepages are disabled.

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        # Ensure that the /sys/kernel/mm/transparent_hugepage/enabled file includes [never].
        # Note this file uses '[]' to denote the chosen option.
        filename = '/sys/kernel/mm/transparent_hugepage/enabled'

        # If we installed 'hugepages' utility by previous invocation of this checker,
        # just go and call it to disable the Transparent Hugepages.
        # We do it on every checker invocation as the utility result doesn't persist reboot :(
        # And it is not easy anymore (since 18.04) to configure Ubuntu to run scripts on startup.
        ret = os.system('dpkg -l | grep hugepages > /dev/null')
        if ret == 0:
            os.system('hugeadm --thp-never')

        # Now perform the check
        with open(filename, "r") as f:
            first_line = f.readlines()[0]
            if re.search('\[never\]', first_line):
                return True

        if not fix:
            print(prompt + "'never' is not chosen in %s" % filename)
            return False

        # Disable transparent hugepages:
        # -----------------------------------------------------------
        # Trial #1:
        # echo never > /sys/kernel/mm/transparent_hugepage/enabled
        # -----------------------------------------------------------
        # filename = '/sys/kernel/mm/transparent_hugepage/enabled'
        # os.system('cp %s %s.orig' % (filename, filename))
        # ret = os.system('echo never > %s' % filename)
        #if ret != 0:
        #    print(prompt + "failed to write 'never' into %s" % (filename))
        #    return False
        # -----------------------------------------------------------
        # Direct editing of doesn't work, so try workaround below!
        # Trial #2:
        # Found here: https://askubuntu.com/questions/597372/how-do-i-modify-sys-kernel-mm-transparent-hugepage-enabled
        # Does not work too!!!
        # -----------------------------------------------------------
        # Trial #3:
        # Install hugepages soft and use it.
        # Seems to work. But requires run of 'hugeadm --thp-never' after every reboot!
        # -----------------------------------------------------------
        ret = os.system('dpkg -l | grep hugepages > /dev/null')
        if ret != 0:
            # Ask user approval to install the 3rd party
            if not silently:
                while True:
                    choice = raw_input(prompt + "install 'hugepages' utility (required for configuration)? [Y/n]: ")
                    if choice == 'y' or choice == 'Y' or choice == '':
                        break
                    elif choice == 'n' or choice == 'N':
                        return False
            cmd = 'apt -y install hugepages'
            ret = os.system(cmd)
            if ret != 0:
                print(prompt + "'%s' failed (%d)" % (cmd,ret))
                return False
        ret = os.system('hugeadm --thp-never')
        if ret != 0:
            print(prompt + "'hugeadm --thp-never' failed (%d)" % (cmd,ret))
            return False
        return True


    def soft_check_hugepage_number(self, fix=False, silently=False, prompt=None):
        """Check if there is enough hugepages available.

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        # This function ensures that "vm.nr_hugepages=1024" appears in /etc/sysctl.d/80-vpp.conf
        vpp_hugepages_file = '/etc/sysctl.d/80-vpp.conf'
        default_hugepages  = 1024

        num_hugepages = None
        try:
            with open(vpp_hugepages_file, 'r') as f:
                for line in f.readlines():
                    if re.match('^[#\s]', line):    # skip commented lines
                        continue
                    match = re.search('hugepages[\s]*=[\s]*([0-9]+)', line)
                    if match:
                        num_hugepages = int(match.group(1))
                        break
        except Exception as e:
            print(prompt + str(e))      # File should be created during vpp installation, so return if not exists!
            return False


        # Even if found, still enable user to configure it in interactive mode
        #if num_hugepages:
        #    return True

        if not fix:
            if num_hugepages is None:
                print(prompt + "'hugepages' was not found in %s" % vpp_hugepages_file)
                return False
            return True

        if silently:
            if num_hugepages is None:   # If not found in file
                ret = os.system('\nprintf "# Number of 2MB hugepages desired\nvm.nr_hugepages=%d\n" >> %s' % (default_hugepages, vpp_hugepages_file))
                if ret != 0:
                    print(prompt + "failed to write hugepages=%d into %s" % (default_hugepages, vpp_hugepages_file))
                    return False
                    os.system('sysctl -p %s' %(vpp_hugepages_file))
                return True
            return True

        # Read parameter from user input
        hugepages = default_hugepages if num_hugepages is None else num_hugepages
        while True:
            str_hugepages = raw_input(prompt + "Enter number of 2MB huge pages [%d]: " % hugepages)
            try:
                if len(str_hugepages) == 0:
                    break
                hugepages = int(str_hugepages)
                break
            except Exception as e:
                print(prompt + str(e))

        if num_hugepages:   # If not None, that means it was found in file, delete it firstly from file
            os.system('sed -i -E "/Number of .* hugepages desired/d" %s' % (vpp_hugepages_file))
            ret = os.system('sed -i -E "/vm.nr_hugepages.*=/d" %s' % (vpp_hugepages_file))
            if ret != 0:
                print(prompt + "failed to remove old hugepages from %s" % (vpp_hugepages_file))
                return False
        # Now add parameter by new line
        ret = os.system('\nprintf "# Number of 2MB hugepages desired\nvm.nr_hugepages=%d\n" >> %s' % (default_hugepages, vpp_hugepages_file))
        if ret != 0:
            print(prompt + "failed to write hugepages=%d into %s" % (hugepages, vpp_hugepages_file))
            return False
        os.system('sysctl -p %s' %(vpp_hugepages_file))
        return True

    def soft_check_dpdk_num_buffers(self, fix=False, silently=False, prompt=None):
        """Check if there is enough DPDK buffers available.

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        # This function sets "num-mbufs 16384" into "dpdk" section in /etc/vpp/startup.conf

        # 'Fix' and 'silently' has no meaning for vpp configuration parameters,
        # as any value is good for it, and if no value was configured,
        # the default will be used.
        if not fix or silently:
            return True

        # Fetch current value if exists
        buffers = 16384  # Set default
        conf    = self.vpp_configuration
        conf_param = None
        if conf and conf['dpdk']:
            key = self.fw_ac_db.get_element(conf['dpdk'], 'num-mbufs')
            if key:
                tup = self.fw_ac_db.get_tuple_from_key(conf['dpdk'], key)
                if tup:
                    buffers = int(tup[0].split(' ')[1])
                    conf_param = tup[0]

        old = buffers
        while True:
            str_buffers = raw_input(prompt + "Enter number of memory buffers per CPU core [%d]: " % (buffers))
            try:
                if len(str_buffers) == 0:
                    break
                buffers = int(str_buffers)
                break
            except Exception as e:
                print(prompt + str(e))

        if old == buffers:
            return True     # No need to update

        if conf_param:
            self.fw_ac_db.remove_element(conf['dpdk'], conf_param)
            conf_param = 'num-mbufs %d' % (buffers)
            tup = self.fw_ac_db.create_element(conf_param)
            conf['dpdk'].append(tup)
            self.vpp_config_modified = True
            return True

        if not conf:
            conf = L([])
        if conf['dpdk'] is None:
            tup = self.fw_ac_db.create_element('dpdk')
            conf.append(tup)
        
        conf['dpdk'].append(self.fw_ac_db.create_element('num-mbufs %d' %(buffers)))
        self.vpp_config_modified = True
        return True

    def soft_check_vpp_workers_core(self, fix=False, silently=False, prompt=''):
        """Check and set number of worker cores to process incoming packets.

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        # This function does the following:
        # 1. sets "main-core", "corelist-worrkers" and "workers" in "cpu" section in /etc/vpp/startup.conf
        # 2. sets "num-rx-queues" in "dpdk" section in /etc/vpp/startup.conf
        # 3. updates "GRUB_CMDLINE_LINUX_DEFAULT" in /etc/defualt/grub
        # 4. sudo update-grub

        if not fix or silently:
            return True
        # 'Fix' and 'silently' has no meaning for vpp configuration parameters,
        # as any value is good for it, and if no value was configured,
        # the exisiting values will be used, or zero if none.

        num_worker_cores = psutil.cpu_count() - 1
        input_cores = 0
        while True:
            str_cores = raw_input(prompt + "Enter number of cores to process packets (max: %d): " % num_worker_cores)
            try:
                if len(str_cores) == 0:
                    break
                input_cores = int(str_cores)
                if input_cores > num_worker_cores:
                    print ("Number of cores entered (%d) was set to maximum available (%d)" % (input_cores, num_worker_cores))
                    input_cores = num_worker_cores
                break
            except Exception as e:
                print(prompt + str(e))

        conf = self.vpp_configuration
        need_to_update = False
        
        main_core_param                 = None
        main_core_param_val             = 0
        corelist_worker_param_nim_val   = 0
        corelist_worker_param_max_val   = 0
        corelist_worker_param           = None
        corelist_worker_param_val       = None
        workers_param                   = None
        workers_param_val               = 0
        num_of_rx_queues_param          = None
        num_of_rx_queues_param_val      = 0
        dev_default_key                 = 'dev default' # to avoid errors and mistypes

        # if configuration files does not exist, create it, and create the 'cpu' and 'dpdk' sections.
        if not conf:
            conf = L([])
        tup = self.fw_ac_db.get_tuple_from_key(conf, 'cpu')
        if tup == None:
            tup = self.fw_ac_db.create_element('cpu')
            conf.append(tup)
            conf['cpu'].append(self.fw_ac_db.create_element('main-core 0')) 
            if input_cores == 0:
                conf['cpu'].append(self.fw_ac_db.create_element('corelist-workers 0'))
            elif input_cores == 1:
                conf['cpu'].append(self.fw_ac_db.create_element('corelist-workers 1'))
            else:
                conf['cpu'].append(self.fw_ac_db.create_element('corelist-workers 1-%d' % (input_cores)))
            conf['cpu'].append(self.fw_ac_db.create_element('workers %d' % (input_cores)))
            self.vpp_config_modified = True
   
        if conf['dpdk']is None:
            conf.append(self.fw_ac_db.create_element('dpdk'))
            self._add_tup_to_dpdk(input_cores)
            self.vpp_config_modified = True
            self.update_grub = True
            return True

        # configuration file exist    
        if conf and conf['cpu']:
            string = self.fw_ac_db.get_element(conf['cpu'],'main-core')
            if string:
                tup_main_core = self.fw_ac_db.get_tuple_from_key(conf['cpu'],string)
                if tup_main_core:
                    main_core_param = tup_main_core[0]
                    main_core_param_val = int(main_core_param.split(' ')[1])
                    
            string = self.fw_ac_db.get_element(conf['cpu'],'corelist-workers')
            if string:
                tup_core_list = self.fw_ac_db.get_tuple_from_key(conf['cpu'],string)
                if tup_core_list:
                    corelist_worker_param = tup_core_list[0]
                    corelist_worker_param_val = corelist_worker_param.split(' ')[1]
                    if corelist_worker_param_val.isdigit():
                        corelist_worker_param_nim_val = corelist_worker_param_max_val = corelist_worker_param_val
                    else:
                        corelist_worker_param_nim_val = int(corelist_worker_param_val.split('-')[0])
                        corelist_worker_param_max_val = int(corelist_worker_param_val.split('-')[1])

            tup_workers = self.fw_ac_db.get_tuple_from_key(conf['cpu'],'workers %s' %(corelist_worker_param_max_val))
            if tup_workers:
                workers_param = tup_workers[0]
                workers_param_val = int(workers_param.split(' ')[1])
 
        if conf and conf['dpdk'] and conf['dpdk'][dev_default_key]:
            lst = conf['dpdk'][dev_default_key]
            string = self.fw_ac_db.get_element(lst,'num-rx-queues')
            if string:
                tup_num_rx = self.fw_ac_db.get_tuple_from_key(lst, string)
                if tup_num_rx:
                    num_of_rx_queues_param = tup_num_rx[0]
                    num_of_rx_queues_param_val = int(num_of_rx_queues_param.split(' ')[1])

        # we assume the following configuration in 'cpu' and 'dpdk' sections:
        # main-core 0
        # corelist_workers 1-%input_cores
        # workers %input_cores
        # num-rx-queues %input_cores
        
        # in case no multi core requested
        if input_cores == 0:
            if main_core_param:
                self.fw_ac_db.remove_element(conf['cpu'], main_core_param)
            main_core_param = 'main-core 0'
            conf['cpu'].append(self.fw_ac_db.create_element(main_core_param))
            
            if corelist_worker_param:
                self.fw_ac_db.remove_element(conf['cpu'], corelist_worker_param)
            corelist_worker_param = 'corelist-workers 0' 
            conf['cpu'].append(self.fw_ac_db.create_element(corelist_worker_param))
            
            if workers_param:
                self.fw_ac_db.remove_element(conf['cpu'], workers_param)
            workers_param = 'workers 0'
            conf['cpu'].append(self.fw_ac_db.create_element(workers_param))

            if num_of_rx_queues_param:
                self.fw_ac_db.remove_element(conf['dpdk'][dev_default_key], num_of_rx_queues_param)
            num_of_rx_queues_param = 'num-rx-queues 0'
            conf['dpdk'][dev_default_key].append(self.fw_ac_db.create_element(num_of_rx_queues_param))

            self.vpp_config_modified = True
            self.update_grub = True
            return True 

        # in case multi core configured
        if input_cores != 0:
            new_main_core_param = 'main-core 0'
            if main_core_param:
                if main_core_param_val != 0:
                    self.fw_ac_db.remove_element(conf['cpu'], main_core_param)
                    conf['cpu'].append(self.fw_ac_db.create_element(new_main_core_param))
                    self.vpp_config_modified = True
            else:
                conf['cpu'].append(self.fw_ac_db.create_element(new_main_core_param))
                self.vpp_config_modified = True

            if input_cores == 1:
                new_corelist_worker_param = 'corelist-workers 1'
            else:
                new_corelist_worker_param = 'corelist-workers 1-%d' % (input_cores)
            if corelist_worker_param:
                if corelist_worker_param_nim_val != 1 or corelist_worker_param_max_val != input_cores:
                    self.fw_ac_db.remove_element(conf['cpu'], corelist_worker_param)
                    conf['cpu'].append(self.fw_ac_db.create_element(new_corelist_worker_param))
                    self.vpp_config_modified = True
            else:
                conf['cpu'].append(self.fw_ac_db.create_element(new_corelist_worker_param))
                self.vpp_config_modified = True

            new_workers_param = 'workers %d' % (input_cores)
            if workers_param:
                if workers_param_val != input_cores:
                    self.fw_ac_db.remove_element(conf['cpu'], workers_param)
                    conf['cpu'].append(self.fw_ac_db.create_element(new_workers_param))
                    self.vpp_config_modified = True
            else:
                conf['cpu'].append(self.fw_ac_db.create_element(new_workers_param))
                self.vpp_config_modified = True

 
            if num_of_rx_queues_param_val != input_cores:
                if conf['dpdk']:
                    if conf['dpdk'][dev_default_key]:
                        new_num_of_rx_queues_param = 'num-rx-queues %d' % (input_cores)
                        string = self.fw_ac_db.get_element(conf['dpdk'][dev_default_key], 'num-rx-queues')
                        if string:
                            tup = self.fw_ac_db.get_tuple_from_key(conf['dpdk'][dev_default_key], string)
                            if tup:
                                self.fw_ac_db.remove_element(conf['dpdk'][dev_default_key], string)
                            conf['dpdk'][dev_default_key].append(self.fw_ac_db.create_element(new_num_of_rx_queues_param))
                    else:
                        self._add_tup_to_dpdk(input_cores)
                        self.vpp_config_modified = True 

            if self.vpp_config_modified == True:
                self.update_grub = True
            return True

    def _add_tup_to_dpdk(self, num_of_cores):
        """ 
        adds 'def default' tuple to 'dpdk' and sets 'num-rx-queue' value

        :param num_of_cores:  num of cores to handle incoming traffic

        :returns True
        """
        # This function does the following:
        # 1. create a new sub tuple in 'dpdk'
        # 2. populated it with num-rx-queues %value
        cfg = self.vpp_configuration
        dev_default_key = 'dev default'
        elem_exist = False
        string = self.fw_ac_db.get_element(cfg['dpdk'], dev_default_key)
        if string:
            tup = self.fw_ac_db.get_tuple_from_key(string)
            if tup:
                elem_exist = True
                tup.append(self.fw_ac_db.create_element('num-rx-queues %d' % (num_of_cores)))

        if elem_exist == False:
            tup = self.fw_ac_db.create_element(dev_default_key)
            cfg['dpdk'].append(tup)
            cfg['dpdk'][dev_default_key].append(self.fw_ac_db.create_element('num-rx-queues %d' % (num_of_cores)))

        return True

    def soft_check_cpu_power_saving(self, fix=False, silently=False, prompt=''):
        """Set power saving on main core: add delay to polling frequancy to main core loop

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        # This function does the following:
        # 1. Ask the user if to emable power saving mode
        # 2. If so, set poll-sleep-usec parameter in startup.conf's unix 
        #    section to some TBD value.

        if not fix or silently:
            return True

        enable_ps_mode  = False
        usec_rest       = 300
        usec            = 0
        conf            = self.vpp_configuration
        conf_param      = None
        if conf and conf['unix']:
            string = self.fw_ac_db.get_element(conf['unix'], 'poll-sleep-usec')
            if string:
                tup = self.fw_ac_db.get_tuple_from_key(conf['unix'],string)
                if tup:
                    usec = int(tup[0].split(' ')[1])
                    conf_param = tup[0]

        while True:
            str_ps_mode = raw_input(prompt + "Enable Power-Saving mode on main core (y/N/q)?")        
            if str_ps_mode == 'Y' or str_ps_mode == 'y':
                enable_ps_mode = True
                break
            elif str_ps_mode == 'N' or str_ps_mode == 'n' or str_ps_mode == '':
                enable_ps_mode = False
                break
            else:
                return True  #nothing to do

        if enable_ps_mode == True:
            if usec == usec_rest:
                return True   #nothing to do    
            else:
                if conf_param:
                    self.fw_ac_db.remove_element(conf['unix'], conf_param)
                conf_param = 'poll-sleep-usec %d' % usec_rest
                conf['unix'].append(self.fw_ac_db.create_element(conf_param))
                self.vpp_config_modified = True
                return True

        if enable_ps_mode == True:
            if not conf:
                conf = L([])
            if conf['unix'] is None:
                tup = self.fw_ac_db.create_element(conf,'unix')
                tup.append(self.fw_ac_db.create_elemen('poll-sleep-usec %d' %(usec_rest)))
            self.vpp_config_modified = True
            return True

        if enable_ps_mode == False:
            if conf_param:
                self.fw_ac_db.remove_element(conf['unix'], conf_param)
                self.vpp_config_modified = True
                return True

        return True         

    def update_grub_file(self):
        """Update /etc/default/grub to work with configured number of cores.
        """
        # This function does the following:
        # 1. check how many cores to update
        # 2. updates "GRUB_CMDLINE_LINUX_DEFAULT" in /etc/defualt/grub
        # 3. sudo update-grub
        if self.update_grub == False:
            return

        num_of_workers_cores = 0
        cfg = self.vpp_configuration
        if cfg and cfg['cpu']:
            for param in cfg['cpu']:
                if 'workers' == param[0:7]:
                    current_workers_param = param
                    num_of_workers_cores = int(current_workers_param.split(' ')[1])

        if num_of_workers_cores == 0:
            update_line = 'GRUB_CMDLINE_LINUX_DEFAULT=\"iommu=pt intel_iommu=on\"'
        elif num_of_workers_cores == 1:
            update_line = 'GRUB_CMDLINE_LINUX_DEFAULT=\"iommu=pt intel_iommu=on isolcpus=1 nohz_full=1 rcu_nocbs=1\"'
        else:
            update_line = 'GRUB_CMDLINE_LINUX_DEFAULT=\"iommu=pt intel_iommu=on isolcpus=1-%d nohz_full=1-%d rcu_nocbs=1-%d\"' % (num_of_workers_cores, num_of_workers_cores, num_of_workers_cores)
        grub_read_file  = '/etc/default/grub'
        grub_write_file = '/etc/default/grub.tmp'

        add_grub_line = False
        read_file  = open(grub_read_file, "r")
        write_file = open(grub_write_file, "w")
        for line in read_file:
            if "GRUB_CMDLINE_LINUX_DEFAULT" in line:
                if line.startswith("#"):
                    write_file.write(line)
                else: 
                    line = "# " + line
                    write_file.write(line)
                    add_grub_line = True
            else:
                write_file.write(line)
                add_grub_line = True
        if add_grub_line == True:
            write_file.write(update_line + '\n')
        write_file.close()
        read_file.close()
        shutil.copyfile (grub_write_file, grub_read_file)
        os.remove (grub_write_file)
        if add_grub_line == True:
            os.system ("sudo update-grub")
        return

