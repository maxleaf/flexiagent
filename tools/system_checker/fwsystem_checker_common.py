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
import fwtool_vpp_startupconf_dict

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)
import fwglobals

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
        self.vpp_configuration      = fwtool_vpp_startupconf_dict.load(self.CFG_VPP_CONF_FILE)
        self.vpp_config_modified    = False
        self.reboot_needed          = False

        supported_nics_filename = os.path.join(os.path.dirname(os.path.realpath(__file__)) , 'dpdk_supported_nics.json')
        with open(supported_nics_filename, 'r') as f:
            self.supported_nics = json.load(f)

    def save_config (self):
        if self.vpp_config_modified:
            fwtool_vpp_startupconf_dict.dump(self.vpp_configuration, self.CFG_VPP_CONF_FILE, debug=self.debug)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.save_config()
            
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
            if len(default_routes) > 1:
                print(prompt + "only one default route is allowed, found %d" % len(default_routes))
                return False  # Return here and do not throw exception as we propose no way to fix that. Replace with exception on demand :)
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
        if conf and conf.get('dpdk'):
            for param in conf['dpdk']:
                if 'num-mbufs' in param:
                    buffers = int(param.split(' ')[1])
                    conf_param = param
                    break
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
            conf['dpdk'].remove(conf_param)
            conf_param = 'num-mbufs %d' % buffers
            conf['dpdk'].append(conf_param)
            self.vpp_config_modified = True
            return True

        if not conf:
            conf = {}
        if conf.get('dpdk') is None:
            conf['dpdk'] = []
        conf['dpdk'].append({ 'num-mbufs' : buffers })
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
            str_cores = raw_input(prompt + "Enter number of cores to process packets (max:[%d]): " % num_worker_cores)
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

        # if configuration files does not exist, create it, and create the 'cpu' and 'dpdk' sections.
        if not conf:
            conf = {}
        if conf.get('cpu') is None:
            conf['cpu'] = []
            conf['cpu'].append('main-core 0')
            if input_cores == 0:
                conf['cpu'].append('corelist-workers 0')
            elif input_cores == 1:
                conf['cpu'].append('corelist-workers 1')
            else:
                conf['cpu'].append('corelist-workers 1-%d' % (input_cores))
            conf['cpu'].append('workers %d' % (input_cores))
            self.vpp_config_modified = True
   
        if conf.get('dpdk') is None:
            conf['dpdk'] = []
            self.add_dict_to_dpdk(input_cores)
            self.vpp_config_modified = True
            if self.vpp_config_modified == True:
                return self.update_grub_file(input_cores)
            else:
                return True

        # configuration file exist    
        if conf and conf.get('cpu'):
            for param in conf['cpu']:
                if 'main-core' in param:
                    main_core_param = param
                    main_core_param_val = int(main_core_param.split(' ')[1])
                    
            for param in conf['cpu']:
                if 'corelist-workers' in param:
                    corelist_worker_param = param
                    corelist_worker_param_val = corelist_worker_param.split(' ')[1]
                    if corelist_worker_param_val.isdigit():
                        corelist_worker_param_nim_val = corelist_worker_param_max_val = corelist_worker_param_val
                    else:
                        corelist_worker_param_nim_val = int(corelist_worker_param_val.split('-')[0])
                        corelist_worker_param_max_val = int(corelist_worker_param_val.split('-')[1])

            for param in conf['cpu']:
                if 'workers' == param[0:7]:
                    workers_param = param
                    workers_param_val = int(workers_param.split(' ')[1])
 
        if conf and conf['dpdk']:
            for element in conf['dpdk']:
                if str(type(element)) == "<class 'ruamel.yaml.comments.CommentedMap'>":
                    for element2 in element['dev default']:
                        if 'num-rx-queues' in element2:
                            num_of_rx_queues_param = element2
                            num_of_rx_queues_param_val = int(num_of_rx_queues_param.split(' ')[1])

        # we assume the following configuration in 'cpu' and 'dpdk' sections:
        # main-core 0
        # corelist_workers 1-%input_cores
        # workers %input_cores
        # num-rx-queues %input_cores
        
        # in case no multi core requested
        if input_cores == 0:
            if main_core_param:
                conf['cpu'].remove(main_core_param)
                main_core_param = 'main-core 0'
                conf['cpu'].append(main_core_param)
            if corelist_worker_param:
                conf['cpu'].remove(corelist_worker_param)
                corelist_worker_param = 'corelist-workers 0' 
                conf['cpu'].append(corelist_worker_param)
            if workers_param:
                conf['cpu'].remove(workers_param)
                workers_param = 'workers 0'
                conf['cpu'].append(workers_param)

            if num_of_rx_queues_param:
                for element in conf['dpdk']:
                    if str(type(element)) == "<class 'ruamel.yaml.comments.CommentedMap'>":
                        if num_of_rx_queues_param in element['dev default']:
                            element['dev default'].remove(num_of_rx_queues_param)
                            num_of_rx_queues_param = 'num-rx-queues 0'
                            element['dev default'].append(num_of_rx_queues_param)   
            self.vpp_config_modified = True 
            return self.update_grub_file(input_cores)

        # in case multi core configured
        if input_cores != 0:
            if main_core_param:
                if main_core_param_val != 0:
                    conf['cpu'].remove(main_core_param)
                    main_core_param = 'main-core 0'
                    conf['cpu'].append(main_core_param)
                    self.vpp_config_modified = True
        
            if corelist_worker_param:
                if corelist_worker_param_nim_val != 1 or corelist_worker_param_max_val != input_cores:
                    conf['cpu'].remove(corelist_worker_param)
                    if input_cores == 1:
                        corelist_worker_param = 'corelist-workers 1'
                    else:
                        corelist_worker_param = 'corelist-workers 1-%d' % (input_cores)
                    conf['cpu'].append(corelist_worker_param)
                    self.vpp_config_modified = True
 
            if workers_param:
                if workers_param_val != input_cores:
                    conf['cpu'].remove(workers_param)
                    workers_param = 'workers %d' % (input_cores)
                    conf['cpu'].append(workers_param)
                    self.vpp_config_modified = True
 
            if num_of_rx_queues_param_val != input_cores:
                if conf.get('dpdk'):
                    dict_found = False
                    for element in conf['dpdk']:
                        if str(type(element)) == "<class 'ruamel.yaml.comments.CommentedMap'>":
                            dict_found = True
                            if num_of_rx_queues_param in element['dev default']:
                                element['dev default'].remove(num_of_rx_queues_param)
                                num_of_rx_queues_param = 'num-rx-queues %d' % (input_cores)
                                element['dev default'].append(num_of_rx_queues_param)
                                self.vpp_config_modified = True   
                    if dict_found == False:
                        self.add_dict_to_dpdk(input_cores)
                        self.vpp_config_modified = True 

            if self.vpp_config_modified == True:
                return self.update_grub_file(input_cores)
            else:
                return True

    def add_dict_to_dpdk(self, num_of_cores):
        """ The configuration file is "translated" to a kind of yaml file.
        conf is the main dictioanry, containing key:value elements.
        dpdk is a key in this dictionary, with a list as a value.
        One of the elements of this list is an un-named sub-dictionary.
        it also contains key:value elements.
        One of it's keys is 'dev default', which is a key to a list.
        This list contains string values, such as 'num-rx-queues some_value'

        So, the function checks if the 'dpdk' list contains a dictionary.
        If not, it creates it, and add the list 'dev default' with one value of
        'num-rx-queues %num_of_cores'

        :param num_of_cores:  num of cores to handle incoming traffic

        :returns True
        """
        # This function does the following:
        # 1. create a new sub directory in 'dpdk'
        # 2. populated it with num-rx-queues %value
        cfg = self.vpp_configuration
        dict_exist = False
        for element in cfg['dpdk']:
            if str(type(element)) == "<class 'ruamel.yaml.comments.CommentedMap'>":
                dict_exist = True
                element['dev default'] = []
                element['dev default'].append('num-rx-queues %d' % (num_of_cores))
                break
        if dict_exist == False:
            cfg['dpdk'].append({'dev default':[]})
            for element in cfg['dpdk']:
                if str(type(element)) == "<class 'ruamel.yaml.comments.CommentedMap'>":
                    element['dev default'].append('num-rx-queues %d' % (num_of_cores))
        return True

    def update_grub_file(self, num_of_workers):
        """Update /etc/default/grub to work with more then 1 core.

        :param num_of_workers:  num of cores to handle incoming traffic

        :returns True if values were changed by user and system needs to reboot or False
        """
        # This function does the following:
        # 1. updates "GRUB_CMDLINE_LINUX_DEFAULT" in /etc/defualt/grub
        # 2. sudo update-grub
        if num_of_workers == 0:
            update_line = 'GRUB_CMDLINE_LINUX_DEFAULT=\"iommu=pt intel_iommu=on\"'
        elif num_of_workers == 1:
            update_line = 'GRUB_CMDLINE_LINUX_DEFAULT=\"iommu=pt intel_iommu=on isolcpus=1 nohz_full=1 rcu_nocbs=1\"'
        else:
            update_line = 'GRUB_CMDLINE_LINUX_DEFAULT=\"iommu=pt intel_iommu=on isolcpus=1-%d nohz_full=1-%d rcu_nocbs=1-%d\"' % (num_of_workers, num_of_workers, num_of_workers)
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
            self.reboot_needed = True
        return True

    def soft_check_worker_cpu_power_saving(self, fix=False, silently=False, prompt=''):
        """Set power saving on worker threads: add none-polling time (delay) to core work

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
        usec_rest       = 100
        conf            = self.vpp_configuration
        conf_param      = None
        if conf and conf.get('unix'):
            for param in conf['unix']:
                if 'poll-sleep-usec' in param:
                    usec = int(param.split(' ')[1])
                    conf_param = param
                    break

        while True:
            str_ps_mode = raw_input(prompt + "Enable Power-Saving mode on worker CPUs (y/N/q)?")        
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

            if conf_param:
                conf['unix'].remove(conf_param)
                conf_param = 'poll-sleep-usec %d' % usec
                conf['unix'].append(conf_param)
                self.vpp_config_modified = True
            return True

            if not conf:
                conf = {}
            if conf.get('unix') is None:
                conf['unix'] = []
            conf['unix'].append({ 'poll-sleep-usec' : usec_rest })
            self.vpp_config_modified = True
            return True

        if enable_ps_mode == False:
            if conf_param:
                conf['unix'].remove(conf_param)
                self.vpp_config_modified = True
                return True

        return True         

        