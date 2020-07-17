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

def _backup_netplan_files():
    for fname in fwglobals.g.NETPLAN_FILES.values():
        fname_backup = fname + '.fworig'
        fname_run = fname.replace('yaml', 'fwrun.yaml')

        if not os.path.exists(fname_run):
            fwglobals.log.debug('_backup_netplan_files: doing backup of %s' % fname)
            shutil.copyfile(fname, fname_backup)
            shutil.move(fname, fname_run)

def _delete_netplan_files():
    files = glob.glob("/etc/netplan/*.yaml") + \
            glob.glob("/lib/netplan/*.yaml") + \
            glob.glob("/run/netplan/*.yaml")

    for fname in files:
        fwglobals.log.debug('_delete_netplan_files: %s' % fname)
        if re.search('fwrun.yaml', fname):
            fname_run = fname
            fname = fname_run.replace('fwrun.yaml', 'yaml')
            fname_backup = fname + '.fworig'

            os.remove(fname_run)
            shutil.move(fname_backup, fname)

def add_del_netplan_file(is_add):
    if is_add:
        _backup_netplan_files()
    else:
        _delete_netplan_files()

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
                        gateway = devices[dev] if dev in devices else None
                        pci = fwutils.linux_to_pci_addr(dev)[0]
                        if fname in our_files:
                            our_files[fname].append({'ifname': dev, 'gateway': gateway, 'pci': pci})
                        else:
                            our_files[fname] = [{'ifname': dev, 'gateway': gateway, 'pci': pci}]
    return our_files

def _set_netplan_filename(files):
    for fname, devices in files.items():
        for dev in devices:
            pci = dev.get('pci')
            ifname = dev.get('ifname')
            if pci:
                fwglobals.g.NETPLAN_FILES[pci] = fname
                fwglobals.log.debug('_set_netplan_filename: %s(%s) uses %s' % (ifname, pci, fname))

def add_remove_netplan_interface(is_add, pci, ip, gw, metric=None, dhcp=None):
    metric = int(metric) if metric else 0
    fname  = fwglobals.g.NETPLAN_FILES[pci].replace('yaml', 'fwrun.yaml')

    config_section = {}
    if dhcp and re.match('yes', dhcp):
        config_section['dhcp4'] = True
        config_section['dhcp4-overrides'] = {'route-metric': metric}
    else:
        config_section['dhcp4'] = False
        config_section['addresses'] = [ip]
        if gw:
            config_section['routes'] = [{'to': '0.0.0.0/0', 'via': gw, 'metric': metric}]

    try:
        with open(fname, 'r') as stream:
            config = yaml.safe_load(stream)
            network = config['network']

        if 'ethernets' not in network:
            network['ethernets'] = {}

        ethernets = network['ethernets']

        tap_name = fwutils.pci_to_tap(pci)
        if is_add == 1:
            if tap_name in ethernets:
                del ethernets[tap_name]
            ethernets[tap_name] = config_section
        else:
            del ethernets[tap_name]

        with open(fname, 'w') as stream:
            yaml.safe_dump(config, stream)

        cmd = 'sudo netplan apply'
        fwglobals.log.debug(cmd)
        subprocess.check_output(cmd, shell=True)
    except Exception as e:
        err = "add_remove_netplan_interface failed: pci: %s, file: %s, error: %s"\
              % (pci, fname, str(e))
        fwglobals.log.error(err)
        pass

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