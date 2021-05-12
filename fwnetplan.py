#! /usr/bin/python3

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
import os
import time
import subprocess
import re
import fwglobals
import fwutils
import shutil
import yaml

from fwwan_monitor import get_wan_failover_metric

def _copyfile(source_name, dest_name, buffer_size=1024*1024):
    with open(source_name, 'r') as source, open(dest_name, 'w') as dest:
        while True:
            copy_buffer = source.read(buffer_size)
            if not copy_buffer:
                break
            fwutils.file_write_and_flush(dest, copy_buffer)

def backup_linux_netplan_files():
    for values in list(fwglobals.g.NETPLAN_FILES.values()):
        fname = values.get('fname')
        fname_backup = fname + '.fw_run_orig'
        fname_run = fname.replace('yaml', 'fwrun.yaml')

        fwglobals.log.debug('_backup_netplan_files: doing backup of %s' % fname)
        if not os.path.exists(fname_backup):
            _copyfile(fname, fname_backup)
        if not os.path.exists(fname_run):
            _copyfile(fname, fname_run)
        if os.path.exists(fname):
            os.remove(fname)

def restore_linux_netplan_files():
    files = glob.glob("/etc/netplan/*.fwrun.yaml") + \
            glob.glob("/lib/netplan/*.fwrun.yaml") + \
            glob.glob("/run/netplan/*.fwrun.yaml")

    for fname in files:
        fname_run = fname
        fname = fname_run.replace('fwrun.yaml', 'yaml')
        fname_backup = fname + '.fw_run_orig'

        if os.path.exists(fname_run):
            os.remove(fname_run)

        if os.path.exists(fname_backup):
            _copyfile(fname_backup, fname)
            os.remove(fname_backup)

    if files:
        fwutils.netplan_apply('restore_linux_netplan_files')

def load_netplan_filenames(get_only=False):
    '''Parses currently active netplan yaml files into dict of device info by
    interface name, where device info is represented by tuple:
    (<netplan filename>, <interface name>, <gw>, <dev_id>, <set-name name>).
    Than the parsed info is loaded into fwglobals.g.NETPLAN_FILES cache.

    :param get_only: if True the parsed info is not loaded into cache.
    '''
    output = subprocess.check_output('ip route show default', shell=True).decode().strip()
    routes = output.splitlines()

    devices = {}
    for route in routes:
        rip = route.split('via ')[1].split(' ')[0]
        dev = route.split('dev ')[1].split(' ')[0]
        devices[dev] = rip

    files = glob.glob("/etc/netplan/*.fw_run_orig") + \
            glob.glob("/lib/netplan/*.fw_run_orig") + \
            glob.glob("/run/netplan/*.fw_run_orig")

    if not files:
        files = glob.glob("/etc/netplan/*.yaml") + \
                glob.glob("/lib/netplan/*.yaml") + \
                glob.glob("/run/netplan/*.yaml")

    fwglobals.log.debug("load_netplan_filenames: %s" % files)

    our_files = {}
    for fname in files:
        with open(fname, 'r') as stream:
            if re.search('fw_run_orig', fname):
                fname = fname.replace('yaml.fw_run_orig', 'yaml')
            config = yaml.safe_load(stream)
            if config is None:
                continue
            if 'network' in config:
                network = config['network']
                if 'ethernets' in network:
                    ethernets = network['ethernets']
                    for dev in ethernets:
                        name = ethernets[dev].get('set-name', '')
                        if name:
                            gateway = devices.get(name)
                            dev_id = fwutils.get_interface_dev_id(name)
                        else:
                            gateway = devices.get(dev)
                            dev_id = fwutils.get_interface_dev_id(dev)
                        if fname in our_files:
                            our_files[fname].append({'ifname': dev, 'gateway': gateway, 'dev_id': dev_id, 'set-name': name})
                        else:
                            our_files[fname] = [{'ifname': dev, 'gateway': gateway, 'dev_id': dev_id, 'set-name': name}]

    if get_only:
        return our_files

    for fname, devices in list(our_files.items()):
        for dev in devices:
            dev_id = dev.get('dev_id')
            ifname = dev.get('ifname')
            set_name = dev.get('set-name')
            if dev_id:
                fwglobals.g.NETPLAN_FILES[dev_id] = {'fname': fname, 'ifname': ifname, 'set-name': set_name}
                fwglobals.log.debug('load_netplan_filenames: %s(%s) uses %s' % (ifname, dev_id, fname))


def _add_netplan_file(fname):
    if os.path.exists(fname):
        return

    config = dict()
    config['network'] = {'version': 2, 'renderer': 'networkd'}
    with open(fname, 'w+') as stream:
        yaml.safe_dump(config, stream, default_flow_style=False)
        stream.flush()
        os.fsync(stream.fileno())

def _dump_netplan_file(fname):
    if fname:
        try:
            with open(fname, 'r') as f:
                fwglobals.log.error("NETPLAN file contents: " + f.read())
        except Exception as e:
            err_str = "_dump_netplan_file failed: file: %s, error: %s"\
              % (fname, str(e))
            fwglobals.log.error(err_str)

def add_remove_netplan_interface(is_add, dev_id, ip, gw, metric, dhcp, type, dnsServers, dnsDomains, mtu=None, if_name=None, dont_check_ip=False):
    '''
    :param metric:  integer (whole number)
    '''
    config_section = {}
    old_ethernets = {}

    fwglobals.log.debug(
        "add_remove_netplan_interface: is_add=%d, dev_id=%s, ip=%s, gw=%s, metric=%d, dhcp=%s, type=%s, \
         dnsServers=%s, dnsDomains=%s, mtu=%s, if_name=%s, dont_check_ip=%s" %
        (is_add, dev_id, ip, gw, metric, dhcp, type, dnsServers, dnsDomains, str(mtu), if_name, str(dont_check_ip)))

    fo_metric = get_wan_failover_metric(dev_id, metric)
    if fo_metric != metric:
        fwglobals.log.debug(
            "add_remove_netplan_interface: dev_id=%s, use wan failover metric %d" % (dev_id, fo_metric))
        metric = fo_metric

    set_name = ''
    old_ifname = ''
    ifname = if_name if if_name else fwutils.dev_id_to_tap(dev_id)
    if not ifname:
        err_str = "add_remove_netplan_interface: %s was not found" % dev_id
        fwglobals.log.error(err_str)
        return (False, err_str)

    dev_id = fwutils.dev_id_to_full(dev_id)
    if dev_id in fwglobals.g.NETPLAN_FILES:
        fname = fwglobals.g.NETPLAN_FILES[dev_id].get('fname')
        fname_run = fname.replace('yaml', 'fwrun.yaml')
        _add_netplan_file(fname_run)

        fname_backup = fname + '.fw_run_orig'

        old_ifname = fwglobals.g.NETPLAN_FILES[dev_id].get('ifname')
        set_name   = fwglobals.g.NETPLAN_FILES[dev_id].get('set-name', '')

        with open(fname_backup, 'r') as stream:
            old_config = yaml.safe_load(stream)
            old_network = old_config['network']
            old_ethernets = old_network['ethernets']
    else:
        fname_run = fwglobals.g.NETPLAN_FILE
        _add_netplan_file(fname_run)

    try:
        with open(fname_run, 'r') as stream:
            config = yaml.safe_load(stream)
            network = config['network']
            network['renderer'] = 'networkd'

        if 'ethernets' not in network:
            network['ethernets'] = {}

        ethernets = network['ethernets']

        if old_ethernets:
            if old_ifname in old_ethernets:
                config_section = old_ethernets[old_ifname]

        if 'dhcp6' in config_section:
            del config_section['dhcp6']

        if mtu:
            config_section['mtu'] = mtu

        if re.match('yes', dhcp):
            if 'addresses' in config_section:
                del config_section['addresses']
            if 'routes' in config_section:
                del config_section['routes']
            if 'gateway4' in config_section:
                del config_section['gateway4']
            if 'nameservers' in config_section:
                del config_section['nameservers']

            config_section['dhcp4'] = True
            config_section['dhcp4-overrides'] = {'route-metric': metric}
        else:
            config_section['dhcp4'] = False
            if 'dhcp4-overrides' in config_section:
                del config_section['dhcp4-overrides']
            if ip:
                config_section['addresses'] = [ip]

            if gw and type == 'WAN':
                default_route_found = False
                routes = config_section.get('routes', [])
                for route in routes:
                    if route['to'] == '0.0.0.0/0':
                        default_route_found = True
                        route['metric']     = metric
                        route['via']        = gw
                        break
                if not default_route_found:
                    routes.append({'to': '0.0.0.0/0', 'via': gw, 'metric': metric})
                    config_section['routes'] = routes   # Handle case where there is no 'routes' section
                if 'gateway4' in config_section:
                    del config_section['gateway4']

                if dnsServers:
                    nameservers = config_section.get('nameservers', {})
                    nameservers['addresses'] = dnsServers
                    config_section['nameservers'] = nameservers
                if dnsDomains:
                    nameservers = config_section.get('nameservers', {})
                    nameservers['search'] = dnsDomains
                    config_section['nameservers'] = nameservers

        is_lte = fwutils.is_lte_interface_by_dev_id(dev_id)
        if is_add == 1:
            if old_ifname in ethernets:
                del ethernets[old_ifname]
            if set_name in ethernets:
                del ethernets[set_name]

            # set-name with LTE causes issue since the Linux LTE interface is not controlled by dpdk
            # and stay in Linux with the vppsb interface. Our LTE solution is to set the IP on the vppsb, and if we use set-name, it stays down.
            # We need to set the IP on the vppsb interface and remove the set-name and match sections. 
            if set_name and not is_lte:
                ethernets[set_name] = config_section
            elif set_name and is_lte:
                del config_section['set-name']
                if 'match' in config_section:
                    del config_section['match']
                ethernets[ifname] = config_section
            else:
                ethernets[ifname] = config_section
        else:
            # This function is called when the VP is running and we do not need to stop it.
            # Hence, if we want to remove an interface (is_add=0), it doesn't mean that we release if from vpp to Linux control
            # But it stays under vpp control, and tap-inject is enable, and we only need to clean up the interface configuration
            if set_name:
                if set_name in ethernets:
                    ethernets[set_name] = {}
                    ethernets[set_name]['dhcp4'] = False
            else:
                if ifname in ethernets:
                    ethernets[ifname] = {}
                    ethernets[ifname]['dhcp4'] = False


        with open(fname_run, 'w') as stream:
            yaml.safe_dump(config, stream)
            stream.flush()
            os.fsync(stream.fileno())

        # Remove default route from ip table because Netplan is not doing it.
        if not is_add and type == 'WAN':
            fwutils.remove_linux_default_route(ifname)

        fwutils.netplan_apply('add_remove_netplan_interface')

        # make sure IP address is applied in Linux.
        if is_add and set_name:
            if set_name != ifname and not is_lte:
                cmd = 'ip link set %s name %s' % (ifname, set_name)
                fwglobals.log.debug(cmd)
                os.system(cmd)
                fwutils.netplan_apply('add_remove_netplan_interface')
                ifname = set_name

        # On interface adding or removal update caches interface related caches.
        #
        if dev_id:
            dev_id_full = fwutils.dev_id_to_full(dev_id)

            # Remove dev-id-to-vpp-if-name and vpp-if-name-to-dev-id cached
            # values for this dev id if the interface is removed from system.
            #
            if is_add == False:
                vpp_if_name = fwglobals.g.cache.dev_id_to_vpp_if_name.get(dev_id_full)
                if vpp_if_name:
                    del fwglobals.g.cache.dev_id_to_vpp_if_name[dev_id_full]
                    del fwglobals.g.cache.vpp_if_name_to_dev_id[vpp_if_name]

            # Remove dev-id-to-tap cached value for this dev id, as netplan might change
            # interface name (see 'set-name' netplan option).
            # As well re-initialize the interface name by dev id.
            # Note 'dev_id' is None for tap-inject (vppX) of tapcli-X interfaces used for LTE/WiFi devices.
            #
            cache = fwglobals.g.cache.dev_id_to_vpp_tap_name
            if dev_id_full in cache:
                del cache[dev_id_full]
            ifname = fwutils.dev_id_to_tap(dev_id)
            fwglobals.log.debug("Interface name in cache is %s, dev_id %s" % (ifname, dev_id_full))

        if not dont_check_ip: # Failover might be easily caused by interface down so no need to validate IP
            if is_add and not _has_ip(ifname, (dhcp=='yes')):
                raise Exception("ip was not assigned")

    except Exception as e:
        err_str = "add_remove_netplan_interface failed: dev_id: %s, file: %s, error: %s"\
              % (dev_id, fname_run, str(e))
        fwglobals.log.error(err_str)
        _dump_netplan_file(fname_run)
        return (False, err_str)

    return (True, None)

def get_dhcp_netplan_interface(if_name):
    files = glob.glob("/etc/netplan/*.yaml") + \
            glob.glob("/lib/netplan/*.yaml") + \
            glob.glob("/run/netplan/*.yaml")

    for fname in files:
        with open(fname, 'r') as stream:
            config = yaml.safe_load(stream)

        if config is None:
            continue

        if 'network' in config:
            network = config['network']

            if 'ethernets' in network:
                ethernets = network['ethernets']

                if if_name in ethernets:
                    interface = ethernets[if_name]
                    if 'dhcp4' in interface:
                        if interface['dhcp4'] == True:
                            return 'yes'
    return 'no'

def _has_ip(if_name, dhcp):

    for i in range(50):
        log = (i == 49) # Log only the last trial to avoid log spamming
        if fwutils.get_interface_address(if_name, log_on_failure=log):
            return True
        time.sleep(1)

    # At this point no IP was found on the interface.
    # If IP was not assigned to the interface, we still return OK if:
    # - DHCP was configured on secondary interface (not default route),
    #   hopefully it will get IP at some time later. Right now we don't
    #   want to fail router-start or router restore on reboot/watchdog.
    #   The fwagent will take care of dhcp interfaces with no IP, while
    #   handling tunnels, static routes, etc.
    #
    # We return error if:
    # - IP was configured statically
    # - DHCP was configured on primary (default route) interface,
    #   as connection to flexiManage will be lost, so we prefer to revert
    #   to the previous configuration
    #
    if dhcp:
        (_, dev, _, _) = fwutils.get_default_route()
        if if_name != dev:
            return True

    return False
