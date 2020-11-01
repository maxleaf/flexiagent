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

    files = glob.glob("/etc/netplan/*.fw_run_orig") + \
            glob.glob("/lib/netplan/*.fw_run_orig") + \
            glob.glob("/run/netplan/*.fw_run_orig")

    if not files:
        files = glob.glob("/etc/netplan/*.yaml") + \
                glob.glob("/lib/netplan/*.yaml") + \
                glob.glob("/run/netplan/*.yaml")

    fwglobals.log.debug("get_netplan_filenames: %s" % files)

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
                        name = _get_netplan_interface_name(dev, ethernets[dev])
                        if name:
                            gateway = devices[name] if name in devices else None
                            dev_id = fwutils.get_interface_dev_id(name)
                        else:
                            gateway = devices[dev] if dev in devices else None
                            dev_id = fwutils.get_interface_dev_id(dev)
                        if fname in our_files:
                            our_files[fname].append({'ifname': dev, 'gateway': gateway, 'dev_id': dev_id, 'set-name': name})
                        else:
                            our_files[fname] = [{'ifname': dev, 'gateway': gateway, 'dev_id': dev_id, 'set-name': name}]
    return our_files

def _set_netplan_filename(files):
    for fname, devices in files.items():
        for dev in devices:
            dev_id = dev.get('dev_id')
            ifname = dev.get('ifname')
            set_name = dev.get('set-name')
            if dev_id:
                fwglobals.g.NETPLAN_FILES[dev_id] = {'fname': fname, 'ifname': ifname, 'set-name': set_name}
                fwglobals.log.debug('_set_netplan_filename: %s(%s) uses %s' % (ifname, dev_id, fname))

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

def add_remove_netplan_interface(is_add, dev_id, ip, gw, metric, dhcp, type):
    config_section = {}
    old_ethernets = {}

    set_name = ''
    old_ifname = ''

    ifname = fwutils.dev_id_to_tap(dev_id)
    if not ifname:
        err_str = "add_remove_netplan_interface: %s was not found" % dev_id
        fwglobals.log.error(err_str)
        return (False, err_str)

    if dev_id in fwglobals.g.NETPLAN_FILES:
        fname = fwglobals.g.NETPLAN_FILES[dev_id].get('fname')
        fname_run = fname.replace('yaml', 'fwrun.yaml')
        if (not os.path.exists(fname_run)):
            _add_netplan_file(fname_run)

        fname_backup = fname + '.fw_run_orig'

        old_ifname = fwglobals.g.NETPLAN_FILES[dev_id].get('ifname')
        if fwglobals.g.NETPLAN_FILES[dev_id].get('set-name'):
            set_name = fwglobals.g.NETPLAN_FILES[dev_id].get('set-name')

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
            config_section['dhcp4'] = True
            config_section['dhcp4-overrides'] = {'route-metric': metric}
            config_section['critical'] = True   # Prevent lease release on networkd restart or no answer from DHCP server
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

            ethernets[ifname] = config_section
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

        # If needed, remove dev-id-to-tap cached value for this dev id, as netplan might change
        # interface name.
        cache = fwglobals.g.get_cache_data('DEV_ID_TO_VPP_TAP_NAME_MAP')
        dev_id = fwutils.dev_id_to_full(dev_id)
        if dev_id in cache:
            del cache[dev_id]

        # make sure IP address is applied in Linux
        if is_add == 1:
            ip_address_is_found = False
            for i in range(50):
                ifname = fwutils.dev_id_to_tap(dev_id)
                if fwutils.get_interface_address(ifname):
                    ip_address_is_found = True
                    break
                if i % 10 == 0:   # Every 10 seconds try whatever might help, e.g. restart networkd
                    cmd = "systemctl restart systemd-networkd"
                    fwglobals.log.debug("add_remove_netplan_interface: " + cmd)
                    os.system(cmd)
                time.sleep(1)
            if not ip_address_is_found:
                err_str = "add_remove_netplan_interface: %s has no ip address" % ifname
                fwglobals.log.error(err_str)
                _dump_netplan_file(fname_run)
                return (False, err_str)

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
