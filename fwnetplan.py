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
    for values in fwglobals.g.NETPLAN_FILES.values():
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
    (<netplan filename>, <interface name>, <gw>, <pci>, <set-name name>).
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
                            pci, _ = fwutils.get_interface_pci(name)
                        else:
                            gateway = devices.get(dev)
                            pci, _ = fwutils.get_interface_pci(dev)
                        if fname in our_files:
                            our_files[fname].append({'ifname': dev, 'gateway': gateway, 'pci': pci, 'set-name': name})
                        else:
                            our_files[fname] = [{'ifname': dev, 'gateway': gateway, 'pci': pci, 'set-name': name}]

    if get_only:
        return our_files

    for fname, devices in our_files.items():
        for dev in devices:
            pci = dev.get('pci')
            ifname = dev.get('ifname')
            set_name = dev.get('set-name')
            if pci:
                fwglobals.g.NETPLAN_FILES[pci] = {'fname': fname, 'ifname': ifname, 'set-name': set_name}
                fwglobals.log.debug('load_netplan_filenames: %s(%s) uses %s' % (ifname, pci, fname))


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

def add_remove_netplan_interface(is_add, pci, ip, gw, metric, dhcp, type, if_name=None, wan_failover=False):
    config_section = {}
    old_ethernets = {}

    fwglobals.log.debug(
        "add_remove_netplan_interface: is_add=%d, pci=%s, ip=%s, gw=%s, metric=%s, dhcp=%s, type=%s" % \
        (is_add, pci, ip, gw, metric, dhcp, type))

    user_metric = 0 if not metric else int(metric)
    fo_metric = get_wan_failover_metric(pci, user_metric)
    if fo_metric != user_metric:
        fwglobals.log.debug(
            "add_remove_netplan_interface: pci=%s, use wan failover metric %d" % (pci, fo_metric))
        metric = str(fo_metric)

    set_name = ''
    old_ifname = ''
    ifname = if_name if if_name else fwutils.pci_to_tap(pci)
    if not ifname:
        err_str = "add_remove_netplan_interface: %s was not found" % pci
        fwglobals.log.error(err_str)
        return (False, err_str)

    if pci in fwglobals.g.NETPLAN_FILES:
        fname = fwglobals.g.NETPLAN_FILES[pci].get('fname')
        fname_run = fname.replace('yaml', 'fwrun.yaml')
        _add_netplan_file(fname_run)

        fname_backup = fname + '.fw_run_orig'

        old_ifname = fwglobals.g.NETPLAN_FILES[pci].get('ifname')
        set_name   = fwglobals.g.NETPLAN_FILES[pci].get('set-name', '')

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
            config_section['addresses'] = [ip]

            if gw and type == 'WAN':
                if 'routes' in config_section:
                    def_route_existed = False
                    routes = config_section['routes']
                    for route in routes:
                        if route['to'] == '0.0.0.0/0':
                            route['metric'] = metric
                            def_route_existed = True
                    if not def_route_existed:
                        routes.append({'to': '0.0.0.0/0',
                                       'via': gw,
                                       'metric': metric})
                else:
                    if 'gateway4' in config_section:
                        del config_section['gateway4']
                    config_section['routes'] = [{'to': '0.0.0.0/0', 'via': gw, 'metric': metric}]

        if is_add == 1:
            if old_ifname in ethernets:
                del ethernets[old_ifname]
            if set_name in ethernets:
                del ethernets[set_name]

            if set_name:
                ethernets[set_name] = config_section
            else:
                ethernets[ifname] = config_section
        else:
            if set_name:
                if set_name in ethernets:
                    del ethernets[set_name]
            else:
                if ifname in ethernets:
                    del ethernets[ifname]
            if old_ethernets:
                if old_ifname in old_ethernets:
                    ethernets[old_ifname] = old_ethernets[old_ifname]

        with open(fname_run, 'w') as stream:
            yaml.safe_dump(config, stream)
            stream.flush()
            os.fsync(stream.fileno())

        fwutils.netplan_apply('add_remove_netplan_interface')

        # make sure IP address is applied in Linux.
        if is_add and set_name:
            if set_name != ifname:
                cmd = 'ip link set %s name %s' % (ifname, set_name)
                fwglobals.log.debug(cmd)
                os.system(cmd)
                fwutils.netplan_apply('add_remove_netplan_interface')
                ifname = set_name

        # Remove pci-to-tap cached value for this pci, as netplan might change
        # interface name (see 'set-name' netplan option).
        # As well re-initialize the interface name by pci.
        #
        cache = fwglobals.g.cache.pci_to_vpp_tap_name
        pci_full = fwutils.pci_to_full(pci)
        if pci_full in cache:
            del cache[pci_full]
        ifname = fwutils.pci_to_tap(pci)
        fwglobals.log.debug("Interface name in cache is %s, pci %s" % (ifname, pci_full))

        if not wan_failover: # Failover might be easily caused by interface down so no need to validate IP
            if is_add and not _has_ip(ifname, (dhcp=='yes')):
                raise Exception("ip was not assigned")

    except Exception as e:
        err_str = "add_remove_netplan_interface failed: pci: %s, file: %s, error: %s"\
              % (pci, fname_run, str(e))
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
        (_, dev, _) = fwutils.get_default_route()
        if if_name != dev:
            return True

    return False
