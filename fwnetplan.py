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
import hashlib
import os
import time
import subprocess
import re
import fwglobals
import fwutils
import shutil
import yaml

def _backup_netplan_files():
    for values in fwglobals.g.NETPLAN_FILES.values():
        fname = values.get('fname')
        fname_backup = fname + '.fworig'

        if not os.path.exists(fname_backup):
            fwglobals.log.debug('_backup_netplan_files: doing backup of %s' % fname)
            shutil.move(fname, fname_backup)

def _delete_netplan_files():
    files = glob.glob("/etc/netplan/*.fwrun.yaml") + \
            glob.glob("/lib/netplan/*.fwrun.yaml") + \
            glob.glob("/run/netplan/*.fwrun.yaml")

    for fname in files:
        fwglobals.log.debug('_delete_netplan_files: %s' % fname)
        fname_run = fname
        fname = fname_run.replace('fwrun.yaml', 'yaml')
        fname_backup = fname + '.fworig'

        os.remove(fname_run)
        if os.path.exists(fname_backup):
            shutil.move(fname_backup, fname)

def add_del_netplan_file(params):
    is_add = params['is_add']
    if is_add:
        _backup_netplan_files()
    else:
        _delete_netplan_files()

    return (True, None)

def _get_netplan_interface_name(name, section):
    if 'set-name' in section:
        return section['set-name']
    return ''

def get_netplan_filenames():
    output = subprocess.check_output('ip route show default', shell=True).strip()
    routes = output.splitlines()

    devices = {}
    for route in routes:
        rip = route.split('via ')[1].split(' ')[0]
        dev = route.split('dev ')[1].split(' ')[0]

        devices[dev] = rip

    files = glob.glob("/etc/netplan/*.yaml") + \
            glob.glob("/lib/netplan/*.yaml") + \
            glob.glob("/run/netplan/*.yaml")

    our_files = {}
    for fname in files:
        with open(fname, 'r') as stream:
            if re.search('fwrun.yaml', fname):
                fname = fname.replace('fwrun.yaml', 'yaml')
            config = yaml.safe_load(stream)
            if 'network' in config:
                network = config['network']
                if 'ethernets' in network:
                    ethernets = network['ethernets']
                    for dev in ethernets:
                        name = _get_netplan_interface_name(dev, ethernets[dev])
                        if name:
                            gateway = devices[name] if name in devices else None
                            pci = fwutils.linux_to_pci_addr(name)[0]
                        else:
                            gateway = devices[dev] if dev in devices else None
                            pci = fwutils.linux_to_pci_addr(dev)[0]

                        device_info = {'ifname': dev, 'gateway': gateway, 'pci': pci, 'set-name': name}
                        fwglobals.log.debug("get_netplan_filenames: %s" % device_info)
                        if fname in our_files:
                            our_files[fname].append(device_info)
                        else:
                            our_files[fname] = [device_info]
    return our_files

def _set_netplan_filename(files):
    for fname, devices in files.items():
        for dev in devices:
            pci = dev.get('pci')
            ifname = dev.get('ifname')
            set_name = dev.get('set-name')
            if pci:
                fwglobals.g.NETPLAN_FILES[pci] = {'fname': fname, 'ifname': ifname, 'set-name': set_name}
                fwglobals.log.debug('_set_netplan_filename: %s(%s) uses %s' % (ifname, pci, fname))

def _add_netplan_file(fname):
    if os.path.exists(fname):
        return

    config = dict()
    config['network'] = {'version': 2}
    with open(fname, 'w+') as stream:
        yaml.safe_dump(config, stream, default_flow_style=False)


def add_remove_netplan_interface(params):
    pci = params['pci']
    is_add = params['is_add']
    dhcp = params['dhcp']
    ip = params['ip']
    gw = params['gw']
    config_section = {}
    old_ethernets = {}
    if params['metric']:
        metric = int(params['metric'])
    else:
        metric = 0

    ifname = fwutils.pci_to_tap(pci)

    if pci in fwglobals.g.NETPLAN_FILES:
        fname = fwglobals.g.NETPLAN_FILES[pci].get('fname')
        fname_run = fname.replace('yaml', 'fwrun.yaml')
        fname_backup = fname + '.fworig'

        if fwglobals.g.NETPLAN_FILES[pci].get('set-name'):
            ifname = fwglobals.g.NETPLAN_FILES[pci].get('set-name')

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

        if 'ethernets' not in network:
            network['ethernets'] = {}

        ethernets = network['ethernets']

        if old_ethernets:
            if ifname in old_ethernets:
                config_section = old_ethernets[ifname]

        if re.match('yes', dhcp):
            config_section['dhcp4'] = True
            config_section['dhcp4-overrides'] = {'route-metric': metric}
        else:
            config_section['dhcp4'] = False
            config_section['addresses'] = [ip]
            if gw is not None and gw:
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
            if ifname in ethernets:
                del ethernets[ifname]
            ethernets[ifname] = config_section
        else:
            if ifname in ethernets:
                del ethernets[ifname]

        with open(fname_run, 'w') as stream:
            yaml.safe_dump(config, stream)

        cmd = 'netplan apply'
        fwglobals.log.debug(cmd)
        subprocess.check_output(cmd, shell=True)

        # make sure IP address is applied in Linux
        if is_add == 1:
            ip_address_is_found = False
            for _ in range(50):
                if fwutils.get_interface_address(ifname):
                    ip_address_is_found = True
                    break
                time.sleep(1)
            if not ip_address_is_found:
                fwglobals.log.error("add_remove_netplan_interface: %s has no ip address" % ifname)
                return (False, None)

    except Exception as e:
        err = "add_remove_netplan_interface failed: pci: %s, file: %s, error: %s"\
              % (pci, fname_run, str(e))
        fwglobals.log.error(err)
        return (False, None)

    return (True, None)

def get_dhcp_netplan_interface(if_name):
    files = glob.glob("/etc/netplan/*.yaml") + \
            glob.glob("/lib/netplan/*.yaml") + \
            glob.glob("/run/netplan/*.yaml")

    for fname in files:
        with open(fname, 'r') as stream:
            config = yaml.safe_load(stream)

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
