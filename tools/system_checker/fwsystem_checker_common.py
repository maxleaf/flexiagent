#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2021  flexiWAN Ltd.
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
from fw_vpp_startupconf import FwStartupConf

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)
import fwglobals
import fwutils
import fwnetplan
from fwsystem_checker import TXT_COLOR

from yaml.constructor import ConstructorError

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


def no_duplicates_constructor(loader, node, deep=False):
    """Check for duplicate keys."""

    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        value = loader.construct_object(value_node, deep=deep)
        if key in mapping:
            raise ConstructorError("", node.start_mark,
                                   "found duplicate key (%s)" % key, key_node.start_mark)
        mapping[key] = value

    return loader.construct_mapping(node, deep)

yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, no_duplicates_constructor)

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
        self.vpp_startup_conf       = FwStartupConf(self.CFG_VPP_CONF_FILE)
        self.vpp_configuration      = self.vpp_startup_conf.get_root_element()
        self.vpp_config_modified    = False
        self.update_grub            = False

        supported_nics_filename = os.path.join(os.path.dirname(os.path.realpath(__file__)) , 'dpdk_supported_nics.json')
        with open(supported_nics_filename, 'r') as f:
            self.supported_nics = json.load(f)

    def save_config (self):
        if self.vpp_config_modified:
            self.vpp_startup_conf.dump(self.vpp_configuration, self.CFG_VPP_CONF_FILE)
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
            self.vpp_startup_conf.dump(self.vpp_configuration, self.CFG_VPP_CONF_FILE)

    def hard_check_sse42(self, supported):
        """Check SSE 4.2 support.

        :param supported:       Unused.

        :returns: 'True' if supported and 'False' otherwise.
        """
        try:
            ret = os.system('cat /proc/cpuinfo | grep sse4_2 > /dev/null 2>&1')
            return ret == 0
        except:
            return False

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
            out = subprocess.check_output("lspci -Dvmmn | grep -cE 'Class:[[:space:]]+02'", shell=True).decode().strip()
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
        def _print_without_line_feed(str):
            # So odd print is needed to enforce no line feed, so next print()
            # will override this line.
            print (str,)
            sys.stdout.flush() # Need this as tail ',' removes the 'newline' in print(), so the print is not flushed immediately

        self.wan_interfaces = []
        interfaces = [ str(iface) for iface in psutil.net_if_addrs() if str(iface) != "lo" ]
        for iface in interfaces:
            for _ in range(5):
                ret = os.system("ping -c 1 -I %s 8.8.8.8 > /dev/null 2>&1" % iface)
                if ret == 0:
                    self.wan_interfaces.append(str(iface))
                    return True
                _print_without_line_feed("\rcheck WAN connectivity on %s" % iface)
            _print_without_line_feed("\r                                              \r")  # Clean the line on screen
        return False

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
                out = subprocess.check_output("lspci -vnn", shell=True).decode().strip().split('\n\n')
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
                    match = re.search('\\[02..\\]:', params[0])   # [02XX] stands for Network Base Class
                    if not match:
                        continue
                    match = re.search('([^ ]+) .*\\[02..\\]: ([^ ]+)', params[0])
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
                if found_uuid == "03000200-0400-0500-0006-000700080009":
                    raise Exception("found UUID is not legal: %s" % found_uuid)
            except ValueError:
                raise Exception("found UUID doesn't comply to RFC: %s" % found_uuid)
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
                choice = input(prompt + "use %s ? [Y/n]: " % new_uuid)
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
            default_routes = subprocess.check_output('ip route | grep default', shell=True).decode().strip().split('\n')
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
            default_routes = subprocess.check_output('ip route | grep default', shell=True).decode().strip().split('\n')
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
                    ip = input(prompt + "please enter GW address, e.g. 192.168.1.1: ")
                    try:
                        out = subprocess.check_output('ip route add default via %s' % ip, shell=True).decode().strip()
                        return True
                    except Exception as e:
                        print(prompt + str(e))
                        while True:
                            choice = input(prompt + "repeat? [Y/n]: ")
                            if choice == 'y' or choice == 'Y' or choice == '':
                                break
                            elif choice == 'n' or choice == 'N':
                                return False

    def _get_duplicate_metric(self):
        output = subprocess.check_output('ip route show default', shell=True).decode().strip()
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

        for metric, gws in list(metrics.items()):
            if len(gws) > 1:
                return metric, metrics

        return None, None

    def _get_gateways(self):
        output = subprocess.check_output('ip route show default', shell=True).decode().strip()
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

        files = fwnetplan.load_netplan_filenames(get_only=True)
        metric = 100
        for fname, devices in list(files.items()):
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

        subprocess.check_call('sudo netplan apply', shell=True)
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
            try:
                self._check_duplicate_netplan_sections()
            except:
                print("Please fix duplicate netplan sections first")
                return False
            duplicates = self._get_duplicate_interface_definitions()
            if duplicates:
                print("Please fix duplicate interface definition in netplan first")
                return False
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
                        id = int(input(prompt + "please choose the gw number: "))
                        if id > len(gws):
                            print("Wrong number chosen!")
                            return False
                        return self._fix_duplicate_metric(gws[id-1])
                    except Exception as e:
                        print(prompt + str(e))
                        while True:
                            choice = input(prompt + "repeat? [Y/n]: ")
                            if choice == 'y' or choice == 'Y' or choice == '':
                                break
                            elif choice == 'n' or choice == 'N':
                                return False
        return True

    def _check_duplicate_netplan_sections(self):
        files = glob.glob("/etc/netplan/*.yaml") + \
                glob.glob("/lib/netplan/*.yaml") + \
                glob.glob("/run/netplan/*.yaml")

        for fname in files:
            with open(fname, 'r') as stream:
                yaml.safe_load(stream)

    def _get_duplicate_interface_definitions(self):
        files = glob.glob("/etc/netplan/*.yaml") + \
                glob.glob("/lib/netplan/*.yaml") + \
                glob.glob("/run/netplan/*.yaml")

        interfaces = {}
        for fname in files:
            with open(fname, 'r') as stream:
                config = yaml.safe_load(stream)
                if 'network' in config:
                    network = config['network']
                    if 'ethernets' in network:
                        ethernets = network['ethernets']
                        for dev in ethernets:
                            if dev not in interfaces:
                                interfaces[dev] = [fname]
                            else:
                                interfaces[dev].append(fname)

        duplicates = {}
        for dev, files in list(interfaces.items()):
            if len(files) > 1:
                duplicates[dev] = files
        return duplicates

    def soft_check_duplicate_netplan_sections(self, fix=False, silently=False, prompt=''):
        """Check if any section is defined multiple times in Netplan files.

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        try:
            self._check_duplicate_netplan_sections()
            return True
        except Exception as e:
            print(prompt + str(e))
            return False
        return True

    def soft_check_multiple_interface_definitions(self, fix=False, silently=False, prompt=''):
        """Check if interface is defined in multiple Netplan files.

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        try:
            duplicates = self._get_duplicate_interface_definitions()
            if duplicates:
                message = "Found multiple interface definitions: "
                for dev, files in list(duplicates.items()):
                    message += dev + ' in '
                    for file in files:
                        message += file + ', '
                raise Exception(message)
            return True
        except Exception as e:
            print(prompt + str(e))
            return False
        return True


    def soft_check_hostname_syntax(self, fix=False, silently=False, prompt=''):
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
        pattern = '^[a-zA-Z0-9\\-_.]{1,253}$'
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
            new_hostname = input(prompt + "enter hostname: ")
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


    def soft_check_hostname_in_hosts(self, fix=False, silently=False, prompt=''):
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
                out = subprocess.check_output("grep '%s' %s" % (address, hosts_file), shell=True).decode().strip().split('\n')[0]
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

    def soft_check_disable_transparent_hugepages(self, fix=False, silently=False, prompt=''):
        """Check if transparent hugepages are disabled.

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        # Ensure that the /sys/kernel/mm/transparent_hugepage/enabled file includes [never].
        # Note this file uses '[]' to denote the chosen option.
        thp_filename = '/sys/kernel/mm/transparent_hugepage/enabled'
        with open(thp_filename, "r") as f:
            first_line = f.readlines()[0]
            if re.search('\\[never\\]', first_line):
                return True
        # Ensure that the /etc/default/grub file includes the "transparent_hugepage=never"
        # option in the GRUB_CMDLINE_LINUX_DEFAULT variable.
        grub_filename = '/etc/default/grub'
        try:
            subprocess.check_call("grep -E '^GRUB_CMDLINE_LINUX_DEFAULT=.*transparent_hugepage=never' %s" % grub_filename,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, shell=True)
            return True   # No exception - grep found the pattern
        except subprocess.CalledProcessError:
            pass

        if not fix:
            print(prompt + "'never' is neither chosen in %s nor defined in %s" % (thp_filename, grub_filename))
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
        # This option requires interactive mode of system checker,
        # so user could approve installation of the third party software.
        # So silent mode does not work! And this confuses a lot.
        # -----------------------------------------------------------
        # Trial #4:
        # Use mix of commands:
        # 1. echo never > /sys/kernel/mm/transparent_hugepage/enabled
        #    This should disable transparent hugepages for current session only.
        #    Next reboot will restore original value.
        # 2. Add "transparent_hugepage=never" to the the GRUB_CMDLINE_LINUX_DEFAULT
        #    option in the /etc/default/grub file.
        #    This should disable transparent hugepages permanently, so it will
        #    survive next and future reboots.
        # -----------------------------------------------------------

        # Move selection (square brackets) to the 'never' option in the transparent_hugepage file.
        # Note the 'echo' below does not override the file, but selects [never] option instead!
        #
        cmd = 'echo never > ' + thp_filename
        ret = os.system(cmd)
        if ret != 0:
            print(prompt + "%s - failed (%d)" % (cmd,ret))
            return False

        # Update the grub file
        #
        cmd = 'sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT=\\\"/GRUB_CMDLINE_LINUX_DEFAULT=\\\"transparent_hugepage=never /" ' + grub_filename
        ret = os.system(cmd)
        if ret != 0:
            print(prompt + "%s - failed (%d)" % (cmd,ret))
            return False
        return True


    def soft_check_hugepage_number(self, fix=False, silently=False, prompt=''):
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
                    if re.match(r'^[#\s]', line):    # skip commented lines
                        continue
                    match = re.search(r'hugepages[\s]*=[\s]*([0-9]+)', line)
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
            str_hugepages = input(prompt + "Enter number of 2MB huge pages [%d]: " % hugepages)
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

    def soft_check_multi_core_support_requires_rss(self, fix=False, silently=False, prompt=''):
        """Check and set number of worker cores to process incoming packets. Requires RSS support

        :param fix:             Fix problem.
        :param silently:        Do not prompt user.
        :param prompt:          User prompt prefix.

        :returns: 'True' if check is successful and 'False' otherwise.
        """
        # This function does the following:
        # 1. sets "main-core" and "corelist-workers" in "cpu" section in /etc/vpp/startup.conf
        # 2. sets "num-rx-queues" in "dpdk" section in /etc/vpp/startup.conf
        # 3. updates "GRUB_CMDLINE_LINUX_DEFAULT" in /etc/default/grub
        # 4. sudo update-grub

        if not fix or silently:
            return True
        # 'Fix' and 'silently' has no meaning for vpp configuration parameters,
        # as any value is good for it, and if no value was configured,
        # the existing values will be used, or zero if none.

        num_worker_cores = psutil.cpu_count() - 1
        input_cores = 0
        while True:
            str_cores = input(prompt + "Enter number of cores to process packets (max: %d): " % num_worker_cores)
            try:
                if len(str_cores) == 0:
                    input_cores = num_worker_cores
                    break
                input_cores = int(str_cores)
                if input_cores > num_worker_cores:
                    print ("Number of cores entered (%d) was set to maximum available (%d)" % (input_cores, num_worker_cores))
                    input_cores = num_worker_cores
                break
            except Exception as e:
                print(prompt + str(e))

        current_workers = self.vpp_startup_conf.get_cpu_workers()
        if current_workers == input_cores:
            return True

        self.vpp_startup_conf.set_cpu_workers(input_cores)
        self.vpp_config_modified = True
        self.update_grub = True
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
            string = self.vpp_startup_conf.get_element(conf['unix'], 'poll-sleep-usec')
            if string:
                tup = self.vpp_startup_conf.get_tuple_from_key(conf['unix'],string)
                if tup:
                    tmp = re.split('\s+', tup[0].strip())
                    usec = int(tmp[1])
                    conf_param = tup[0]

        while True:
            str_ps_mode = input(prompt + "Enable Power-Saving mode on main core (y/N/q)?")
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
            elif not conf:
                    conf = self.vpp_startup_conf.get_root_element()
                    if conf['unix'] is None:
                        tup = self.vpp_startup_conf.create_element(conf,'unix')
                        tup.append(self.vpp_startup_conf.create_element('poll-sleep-usec %d' %(usec_rest)))
                        self.vpp_config_modified = True
                        return True
            else:
                if conf_param:
                    self.vpp_startup_conf.remove_element(conf['unix'], conf_param)
                conf_param = 'poll-sleep-usec %d' % usec_rest
                conf['unix'].append(self.vpp_startup_conf.create_element(conf_param))
                self.vpp_config_modified = True
                return True
        else: # enable_ps_mode is False
            if conf_param:
                self.vpp_startup_conf.remove_element(conf['unix'], conf_param)
                self.vpp_config_modified = True
                return True

        return True

    def update_grub_file(self, reset=False):
        """Update /etc/default/grub to work with configured number of cores.
        """
        # This function does the following:
        # 1. check how many cores to update
        # 2. updates "GRUB_CMDLINE_LINUX_DEFAULT" in /etc/defualt/grub
        # 3. sudo update-grub
        if self.update_grub == False:
            return

        num_of_workers_cores = 0
        # if reset is True, the cfg points to the old configuration while we
        # already copied the startup.conf.restore to startup.conf, so we can't
        # take the old number of workers from the current DB. In case of reset,
        # we need to explicit set the number of cores to zero.
        if reset==False:
            cfg = self.vpp_configuration
            if cfg and cfg['cpu']:
                string = self.vpp_startup_conf.get_element(cfg['cpu'],'corelist-workers')
                if string:
                    tup_core_list = self.vpp_startup_conf.get_tuple_from_key(cfg['cpu'],string)
                    if tup_core_list:
                        corelist_worker_param = tup_core_list[0]
                        tmp = re.split('\s+', corelist_worker_param.strip())
                        corelist_worker_param_val = tmp[1]
                        if corelist_worker_param_val.isdigit():
                            corelist_worker_param_min_val = corelist_worker_param_max_val = int(corelist_worker_param_val)
                        else:
                            corelist_worker_param_min_val = int(corelist_worker_param_val.split('-')[0])
                            corelist_worker_param_max_val = int(corelist_worker_param_val.split('-')[1])
                        num_of_workers_cores = corelist_worker_param_max_val + 1 - corelist_worker_param_min_val

        update_line = ''
        if num_of_workers_cores == 0:
            update_line = ''
        else:
            if fwutils.check_if_virtual_environment() == True:
                update_line += 'iommu=pt intel_iommu=on '
            if num_of_workers_cores == 1:
                update_line += 'isolcpus=1 nohz_full=1 rcu_nocbs=1'
            else:
                update_line += 'isolcpus=1-%d nohz_full=1-%d rcu_nocbs=1-%d' % (num_of_workers_cores, num_of_workers_cores, num_of_workers_cores)
        grub_read_file  = '/etc/default/grub'
        grub_write_file = '/etc/default/grub.tmp'

        add_grub_line = False
        grub_line_found = False
        grub_line = ''
        prefix_val = "GRUB_CMDLINE_LINUX_DEFAULT"
        read_file  = open(grub_read_file, "r")
        write_file = open(grub_write_file, "w")
        for line in read_file:
            if prefix_val in line:
                # no need to handle lines which are remarked
                if line.startswith("#"):
                    write_file.write(line)
                else:
                    #if line is found, remark it, and save its contents for later processing
                    grub_line_found = True
                    grub_line = line
                    line = "# "+line
                    write_file.write(line)
            else:
                write_file.write(line)

    # remove old values if exist, so we can replace with ours.
    # zero cores means reset to old line, without our additions
        if grub_line_found == True:
            add_grub_line = True
            # take the list of values after the 'GRUB_CMDLINE_LINUX_DEFAULT=' part, if exist
            splt = grub_line.split('=\"')
            if len(splt) > 1:
                val_line = splt[1].strip().strip('\" ')
            else:
                val_line = ''
            #create a list of tokens from the val_line
            val_line_list = re.split('\s+', val_line.strip())
            #remove old values, if exist, so we can replace them with ours
            results = []
            for elem in val_line_list:
                if elem.startswith('iommu'):
                    continue
                elif elem.startswith('intel_iommu'):
                    continue
                elif elem.startswith('isolcpus'):
                    continue
                elif elem.startswith('nohz_full'):
                    continue
                elif elem.startswith('rcu_nocbs'):
                    continue
                results.append(elem)
            #regroup val_line
            val_line = " ".join(results)

            #add our values.
            if num_of_workers_cores!=0:
                grub_line = prefix_val+ '=\"' + val_line + " " + update_line + '\"'
            else:
                grub_line = prefix_val+ '=\"' + val_line +'\"'
            write_file.write(grub_line+'\n')
        else:
            grub_line = prefix_val+ '=\"' + update_line + '\"'
            write_file.write(grub_line+'\n')

        write_file.close()
        read_file.close()
        shutil.copyfile (grub_write_file, grub_read_file)
        os.remove (grub_write_file)
        if add_grub_line == True:
            os.system ("sudo update-grub")
        return

    def soft_check_lte_modem_configured_in_mbim_mode(self, fix=False, silently=False, prompt=''):
        lte_interfaces = []
        for nicname, addrs in list(psutil.net_if_addrs().items()):
            driver = fwutils.get_interface_driver(nicname, cache=False)
            if driver and driver in ['cdc_mbim', 'qmi_wwan']:
                dev_id = fwutils.get_interface_dev_id(nicname)
                if dev_id:
                    lte_interfaces.append({'driver': driver, 'dev_id': dev_id})

        if not lte_interfaces:
            raise Exception("No LTE device was detected")

        for inf in lte_interfaces:
            if inf['driver'] == 'qmi_wwan':
                if not fix:
                    return False
                success, _ = fwutils.lte_set_modem_to_mbim(inf['dev_id'])
                if not success:
                    return False
        return True

    def soft_check_wifi_driver(self, fix=False, silently=False, prompt=''):
        other_wifi_drivers = False
        for nicname, addrs in list(psutil.net_if_addrs().items()):
            if not fwutils.is_wifi_interface(nicname):
                continue
                
            driver = fwutils.get_interface_driver(nicname, cache=False)
            if not driver in ['ath10k_pci', 'ath9k_pci']:
                other_wifi_drivers = True
                continue
            
            # Check if driver is a kernel driver or a dkms driver
            driver_info = subprocess.check_output('modinfo %s | grep filename' % driver, shell=True).decode().strip()               
            
            # If driver is already dkms, we can return True
            if 'dkms' in driver_info:
                return True

            # Make sure that driver is a kernel driver
            if not 'kernel' in driver_info:
                continue
            
            # At this point, we sure that we need to replace the existing driver with our one
            if not fix:
                return False
            
            if silently:
                print(TXT_COLOR.BG_WARNING + "Installing new driver... that might takes a few minutes" + TXT_COLOR.END)
                choice = "Y"
            else:
                choice = input(TXT_COLOR.BG_WARNING + "New driver installation is needed, that takes a few minutes. Continue? [Y/N]: " + TXT_COLOR.END)

            if choice != 'y' and choice != 'Y':
                return False
            
            modules = [
                'ath10k_pci',
                'ath10k_core',
                'ath',
                'mac80211',
                'cfg80211',
                'libarc4'
            ]

            try:
                os.system('apt update >> %s 2>&1' % fwglobals.g.SYSTEM_CHECKER_LOG_FILE)
                os.system('apt install -y flexiwan-%s-dkms >> %s 2>&1' % (driver.split('_')[0], fwglobals.g.SYSTEM_CHECKER_LOG_FILE))

                for module in modules:
                    os.system('rmmod %s 2>/dev/null' % module)

                for module in modules:
                    os.system('modprobe %s 2>/dev/null' % module)
            except Exception as e:
                print('Error: %s' % str(e))
                for module in modules:
                    os.system('modprobe %s 2>/dev/null' % module)
                return False
                
            # At this point, the driver installed and compailed successfully. 
            # We can return True even we are inside the loop, 
            # since wo don't need to run it for each WiFi interface.
            return True

        if other_wifi_drivers:
            return True

        raise Exception("No WiFi device was detected")