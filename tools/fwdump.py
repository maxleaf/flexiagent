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


# This script collects various information about FlexiWAN Edge device, e.g.
# configuration of router, fwagent logs, interface configuration in Linux, etc.
# Every piece of data is dumped into dedicated file in temporary folder,
# than whole folder is tar-ed and is zipped.


import os
import re
import subprocess
import sys
import time

agent_root_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..')
sys.path.append(agent_root_dir)
import fwutils
import fwglobals
from fw_vpp_coredump_utils import vpp_coredump_copy_cores

g = fwglobals.Fwglobals()

# Special variables in the dumper commands are substituted in run time as follows:
#   <dumper_out_file> -> '<temporary_folder>/<dumper>.log'
#   <temp_folder>     -> current folder or --temp_folder script argument

g_dumpers = {
    ############################################################################
    # Linux stuff - !!! PLEASE KEEP ALPHABET ORDER !!!
    #
    'linux_cpu':                    { 'shell_cmd': 'cat /proc/cpuinfo > <dumper_out_file>' },
    'linux_dhcpd':                  { 'shell_cmd': 'mkdir -p <temp_folder>/linux_dhcpd/ && ' +
                                                   'cp /etc/dhcp/dhcpd.conf* <temp_folder>/linux_dhcpd 2>/dev/null ; ' +
                                                   'cp /var/log/dhcpd.log    <temp_folder>/linux_dhcpd 2>/dev/null ; ' +
                                                   'true' },       # Add 'true' to avoid error status code returned by shell_cmd if file does not exists
    'linux_disk':                   { 'shell_cmd': 'df -h > <dumper_out_file>' },
    'linux_dpdk_devbind_status':    { 'shell_cmd': 'dpdk-devbind -s > <dumper_out_file>' },
    'linux_grub':                   { 'shell_cmd': 'cp /etc/default/grub <temp_folder>/linux_grub.log 2>/dev/null ; ' +
                                                   'true' },       # Add 'true' to avoid error status code returned by shell_cmd if file does not exists
    'linux_interfaces':             { 'shell_cmd': 'ip addr > <dumper_out_file>' },
    'linux_lsb_release':            { 'shell_cmd': 'cp /etc/lsb-release <temp_folder>/linux_lsb-release.log 2>/dev/null ; ' +
                                                   'true' },       # Add 'true' to avoid error status code returned by shell_cmd if file does not exists
    'linux_lspci':                  { 'shell_cmd': 'lspci -Dvmmn > <dumper_out_file>' },
    'linux_meminfo':                { 'shell_cmd': 'cat /proc/meminfo > <dumper_out_file>' },
    'linux_neighbors':              { 'shell_cmd': 'ip neigh > <dumper_out_file>' },
    'linux_netplan':                { 'shell_cmd': 'mkdir -p <temp_folder>/linux_netplan/etc/ && ' +
                                                   'cp /etc/netplan/*yaml* <temp_folder>/linux_netplan/etc 2>/dev/null && ' +
                                                   'mkdir -p <temp_folder>/linux_netplan/lib/ && ' +
                                                   'cp /lib/netplan/*yaml* <temp_folder>/linux_netplan/lib 2>/dev/null ; ' +
                                                   'mkdir -p <temp_folder>/linux_netplan/run/ && ' +
                                                   'cp /run/netplan/*yaml* <temp_folder>/linux_netplan/run 2>/dev/null ;' +
                                                   'true' },       # Add 'true' to avoid error status code returned by shell_cmd if file does not exists
    'linux_pidof_vpp':              { 'shell_cmd': 'echo "vpp: $(pidof vpp)" > <dumper_out_file>; ' +
                                                   'echo "vppctl: $(pidof vppctl)" >> <dumper_out_file>; ' +
                                                   'ps -elf | grep vpp >> <dumper_out_file>' },
    'linux_ram':                    { 'shell_cmd': 'free > <dumper_out_file>' },
    'linux_resolvconf':             { 'shell_cmd': 'mkdir -p <temp_folder>/linux_resolvconf/ && ' +
                                                   'cp /etc/resolv.conf <temp_folder>/linux_resolvconf 2>/dev/null ; ' +
                                                   'cp /etc/resolvconf/resolv.conf.d/base   <temp_folder>/linux_resolvconf 2>/dev/null ; ' +
                                                   'cp /etc/resolvconf/resolv.conf.d/head   <temp_folder>/linux_resolvconf 2>/dev/null ; ' +
                                                   'cp /etc/resolvconf/resolv.conf.d/tail   <temp_folder>/linux_resolvconf 2>/dev/null ; ' +
                                                   'true' },       # Add 'true' to avoid error status code returned by shell_cmd if file does not exists
    'linux_routes':                 { 'shell_cmd': 'ip route > <dumper_out_file>' },
    'linux_sys_class_net':          { 'shell_cmd': 'ls -l /sys/class/net/ > <dumper_out_file>' },
    'linux_syslog':                 { 'shell_cmd': 'cp /var/log/syslog <temp_folder>/linux_syslog.log 2>/dev/null ;' +
                                                   'true' },       # Add 'true' to avoid error status code returned by shell_cmd if file does not exists
    'linux_syslog.1':               { 'shell_cmd': 'cp /var/log/syslog.1 <temp_folder>/linux_syslog_1.log 2>/dev/null ;' +
                                                   'true' },       # Add 'true' to avoid error status code returned by shell_cmd if file does not exists

    ############################################################################
    # VPP related stuff in Linux - !!! PLEASE KEEP ALPHABET ORDER !!!
    #
    'linux_vpp_api_trace':          { 'shell_cmd': 'cp /tmp/*%s <temp_folder>/ 2>/dev/null ;' % g.VPP_TRACE_FILE_EXT +
                                                   'true' },       # Add 'true' to avoid error status code returned by shell_cmd if file does not exists
    'linux_vpp_startup_conf':       { 'shell_cmd': 'mkdir -p <temp_folder>/vpp_startup_conf && cp /etc/vpp/* <temp_folder>/vpp_startup_conf/ 2>/dev/null ;' +
                                                   'true' },       # Add 'true' to avoid error status code returned by shell_cmd if file does not exists

    ############################################################################
    # FRR stuff - !!! PLEASE KEEP ALPHABET ORDER !!!
    #
    'frr_conf':                     { 'shell_cmd': 'mkdir -p <temp_folder>/frr && cp /etc/frr/* <temp_folder>/frr/ 2>/dev/null' },

    ############################################################################
    # flexiEdge agent stuff - !!! PLEASE KEEP ALPHABET ORDER !!!
    #
    'fwagent_cache':                { 'shell_cmd': 'fwagent show --agent cache > <dumper_out_file>' },
    'fwagent_conf':                 { 'shell_cmd': 'mkdir -p <temp_folder>/fwagent && ' +
                                                   'cp -r /etc/flexiwan/agent/* <temp_folder>/fwagent/ 2>/dev/null' },
    'fwagent_device_signature':     { 'shell_cmd': 'fwagent show --configuration signature > <dumper_out_file>' },
    'fwagent_logs': 				{ 'shell_cmd': 'mkdir -p <temp_folder>/flexiwan_logs && ' +
                                                   'cp /var/log/flexiwan/*.log /var/log/flexiwan/*.log.1 <temp_folder>/flexiwan_logs/ 2>/dev/null ;' +
                                                   'mv <temp_folder>/flexiwan_logs/agent.log <temp_folder>/fwagent.log 2>/dev/null ;' +  # Move main log into root folder for convenience
                                                   'true' },       # Add 'true' to avoid error status code returned by shell_cmd if file does not exists
    'dpkg_log':                     { 'shell_cmd': 'cp /var/log/dpkg.log <temp_folder>/dpkg.log 2>/dev/null ;' +
                                                   'true' },       # Add 'true' to avoid error status code returned by shell_cmd if file does not exists
    'dpkg_log.1':                   { 'shell_cmd': 'cp /var/log/dpkg.log.1 <temp_folder>/dpkg_1.log 2>/dev/null ;' +
                                                   'true' },       # Add 'true' to avoid error status code returned by shell_cmd if file does not exists

    'hostapd.log':                  { 'shell_cmd': 'cp %s <temp_folder>/hostapd.log 2>/dev/null ;' % (g.HOSTAPD_LOG_FILE) +
                                                   'true' },       # Add 'true' to avoid error status code returned by shell_cmd if file does not exists

    'fwagent_db_applications':      { 'shell_cmd': 'fwagent show --database applications > <dumper_out_file>' },
    'fwagent_db_general':           { 'shell_cmd': 'fwagent show --database general > <dumper_out_file>' },
    'fwagent_db_multilink':         { 'shell_cmd': 'fwagent show --database multilink > <dumper_out_file>' },
    'fwagent_multilink_cfg':        { 'shell_cmd': 'fwagent show --configuration multilink-policy > <dumper_out_file>' },
    'fwagent_router_cfg':           { 'shell_cmd': 'fwagent show --configuration router > <dumper_out_file>' },
    'fwagent_system_configuration': { 'shell_cmd': 'fwagent show --configuration system > <dumper_out_file>' },

    'fwagent_threads':              { 'shell_cmd': 'fwagent show --agent threads > <dumper_out_file>' },
    'fwagent_version':              { 'shell_cmd': 'fwagent version > <dumper_out_file>' },

    'fwsystem_checker':             { 'shell_cmd': 'fwsystem_checker --check_only > <dumper_out_file>' },

    ############################################################################
    # VPP stuff - !!! PLEASE KEEP ALPHABET ORDER !!!
    #
    'vpp_acl_dump':                 { 'shell_cmd': 'echo acl_dump > vat.txt && vpp_api_test script in vat.txt > <dumper_out_file> 2>&1 ; rm -rf vat.txt' },
    'vpp_acl_plugin_interface_acl': { 'shell_cmd': 'vppctl show acl-plugin interface > <dumper_out_file>' },
    'vpp_acl_plugin_lookup_context':{ 'shell_cmd': 'vppctl show acl-plugin lookup context > <dumper_out_file>' },
    'vpp_acl_plugin_sessions':      { 'shell_cmd': 'vppctl show acl-plugin sessions > <dumper_out_file>' },
    'vpp_acl_plugin_tables':        { 'shell_cmd': 'vppctl show acl-plugin tables > <dumper_out_file>' },
    'vpp_adj':                      { 'shell_cmd': 'vppctl sh adj > <dumper_out_file>' },
    'vpp_bridge':                   { 'shell_cmd': 'vppctl sh bridge > <dumper_out_file>' },
    'vpp_buffers':                  { 'shell_cmd': 'vppctl sh buffers > <dumper_out_file>' },
    'vpp_ike_sa':                   { 'shell_cmd': 'vppctl sh ike sa > <dumper_out_file>' },
    'vpp_interfaces_addresses':     { 'shell_cmd': 'vppctl sh int addr > <dumper_out_file>' },
    'vpp_interfaces_hw':            { 'shell_cmd': 'vppctl sh hard > <dumper_out_file>' },
    'vpp_interfaces_rx_placement':  { 'shell_cmd': 'vppctl sh int rx > <dumper_out_file>' },
    'vpp_interfaces_sw':            { 'shell_cmd': 'vppctl sh int > <dumper_out_file>' },
    'vpp_interfaces_vmxnet3':       { 'shell_cmd': 'vppctl sh vmxnet3 > <dumper_out_file>' },
    'vpp_ipsec_sa':                 { 'shell_cmd': 'vppctl sh ipsec sa > <dumper_out_file>' },
    'vpp_ipsec_tunnel':             { 'shell_cmd': 'vppctl sh ipsec tunnel > <dumper_out_file>' },
    'vpp_fib_entries':              { 'shell_cmd': 'vppctl sh fib entry > <dumper_out_file>' },
    'vpp_fib_paths':                { 'shell_cmd': 'vppctl sh fib paths > <dumper_out_file>' },
    'vpp_fib_pathlists':            { 'shell_cmd': 'vppctl sh fib path-lists > <dumper_out_file>' },
    'vpp_fwabf_labels':             { 'shell_cmd': 'vppctl sh fwabf label > <dumper_out_file>' },
    'vpp_fwabf_links':              { 'shell_cmd': 'vppctl sh fwabf link > <dumper_out_file>' },
    'vpp_fwabf_policies':           { 'shell_cmd': 'vppctl sh fwabf policy > <dumper_out_file>' },
    'vpp_fwabf_attachments':        { 'shell_cmd': 'vppctl sh fwabf attach > <dumper_out_file>' },
    'vpp_nat44_addresses':          { 'shell_cmd': 'vppctl show nat44 addresses verbose > <dumper_out_file>' },
    'vpp_nat44_hash_tables':        { 'shell_cmd': 'vppctl show nat44 hash tables > <dumper_out_file>' },
    'vpp_nat44_interfaces':         { 'shell_cmd': 'vppctl show nat44 interfaces > <dumper_out_file>' },
    'vpp_nat44_interface_address':  { 'shell_cmd': 'vppctl show nat44 interface address > <dumper_out_file>' },
    'vpp_nat44_static_mappings':    { 'shell_cmd': 'vppctl show nat44 static mappings > <dumper_out_file>' },
    'vpp_nat44_sessions':           { 'shell_cmd': 'vppctl show nat44 sessions > <dumper_out_file>' },
    'vpp_nat44_summary':            { 'shell_cmd': 'vppctl show nat44 summary > <dumper_out_file>' },    
    'vpp_tap_inject':               { 'shell_cmd': 'vppctl show tap-inject > <dumper_out_file>' },
    'vpp_vxlan_tunnel':             { 'shell_cmd': 'vppctl sh vxlan tunnel > <dumper_out_file>' },
}

class FwDump:
    def __init__(self, temp_folder=None, quiet=False, include_vpp_core=None):

        self.temp_folder    = temp_folder
        self.quiet          = quiet
        self.prompt         = 'fwdump>> '
        self.zip_file       = None
        self.hostname       = os.uname()[1]
        self.include_vpp_core = include_vpp_core

        if not temp_folder:
            timestamp = fwutils.build_timestamped_filename('')
            self.temp_folder = os.path.join(os.getcwd(), timestamp)

        # Create temporary folder
        #
        if os.path.exists(self.temp_folder):
            choice = input(self.prompt + "the temporary folder '%s' exists, overwrite? [Y/n]: " % self.temp_folder) \
                     if not self.quiet else 'y'
            if choice == 'y' or choice == 'Y' or choice == '':
                os.system("rm -rf %s" % self.temp_folder)   # shutil.rmtree() fails sometimes on VBox shared folders!
                time.sleep(1)  # Give system a time to remove fd
                os.mkdir(self.temp_folder)
        else:
            os.mkdir(self.temp_folder)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        if self.zip_file:   # If zip was created, delete temporary folder
            os.system("rm -rf %s" % self.temp_folder)   # shutil.rmtree() fails sometimes on VBox shared folders!

    def _dump(self, dumpers):
        '''Run dumpers provided by the 'dumpers' list argument.
        The list contains names of dumpers that serve as keys for the global
        g_dumpers map.
        '''
        try:
            vpp_pid = subprocess.check_output(['pidof', 'vpp']).decode()
        except:
            vpp_pid = None

        for dumper in dumpers:
            if not dumper in g_dumpers:
                print(self.prompt + 'WARNING: %s dumper is not defined' % dumper)
                continue
            if re.match('vpp_', dumper) and not vpp_pid:
                continue        # Escape vpp dumpers if vpp does not run
            output_file = os.path.join(self.temp_folder, '%s.log' % dumper)
            if os.path.exists(output_file):
                continue        # Same dumper might be run by different modules
            if 'shell_cmd' in g_dumpers[dumper]:
                cmd = g_dumpers[dumper]['shell_cmd']
                # Substitute special variables
                cmd = re.sub('<temp_folder>', self.temp_folder, cmd)
                cmd = re.sub('<dumper_out_file>', output_file, cmd)
                try:
                    subprocess.check_call(cmd, shell=True)
                except Exception as e:
                    print(self.prompt + 'warning: dumper %s failed, error %s' % (dumper, str(e)))
                    continue

    def zip(self, filename=None, path=None, delete_temp_folder=True):
        if not filename:
            filename = fwutils.build_timestamped_filename('fwdump_%s' % self.hostname, '.tar.gz')
        if path:
            filename = os.path.join(path, filename)
        self.zip_file = filename

        cmd = 'tar -zcf %s -C %s .' % (self.zip_file, self.temp_folder)
        try:
            if path and not os.path.exists(path):
                os.system('mkdir -p %s > /dev/null 2>&1' % path)
            subprocess.check_call(cmd, shell=True)
        except Exception as e:
            print(self.prompt + 'ERROR: "%s" failed: %s' % (cmd, str(e)))

    def dump_all(self):
        dumpers = list(g_dumpers.keys())
        self._dump(dumpers)
        if self.include_vpp_core:
            corefile_dir = self.temp_folder + "/corefiles/"
            os.makedirs(corefile_dir)
            vpp_coredump_copy_cores(corefile_dir, self.include_vpp_core)

    def dump_multilink(self):
        dumpers = [
                    'linux_interfaces',
                    'linux_neighbors',
                    'linux_pidof_vpp',
                    'linux_routes',
                    'fwagent_log',
                    'fwagent_log.1',
                    'fwagent_multilink_cfg',
                    'fwagent_router_cfg',
                    'vpp_acl_dump',
                    'vpp_fib_entries',
                    'vpp_fib_paths',
                    'vpp_fib_pathlists',
                    'vpp_fwabf_labels',
                    'vpp_fwabf_links',
                    'vpp_fwabf_policies',
                    'vpp_fwabf_attachments',
                    'vpp_interfaces_hw',
                    'vpp_interfaces_sw',
                    'vpp_interfaces_addresses'
                    ]
        self._dump(dumpers)

def main(args):
    with FwDump(temp_folder=args.temp_folder, quiet=args.quiet,
                include_vpp_core=args.include_vpp_core) as dump:

        if args.feature:
            method_name = 'dump_'+ args.feature
            feature_func = getattr(dump, method_name, None)
            if not feature_func:
                print(dump.prompt + "ERROR: %s feature is not supported" % args.feature)
            else:
                feature_func()
        else:
            dump.dump_all()

        if args.dont_zip == False:
            dump.zip(filename=args.zip_file, path=args.dest_folder)
            print(dump.prompt + 'done: %s' % dump.zip_file)
        else:
            print(dump.prompt + 'done: %s' % dump.temp_folder)


if __name__ == '__main__':
    import argparse
    global arg

    if not fwutils.check_root_access():
        sys.exit(1)

    parser = argparse.ArgumentParser(description='FlexiEdge dump utility')
    parser.add_argument('--dest_folder', default=None,
                        help="folder where to put the resulted zip. If not specified, the current dir is used.")
    parser.add_argument('--dont_zip', action='store_true',
                        help="don't archive dumped data into single file. Path to folder with dumps will be printed on exit.")
    parser.add_argument('--feature', choices=['multilink'], default=None,
                        help="dump info related to this feature only")
    parser.add_argument('-q', '--quiet', action='store_true',
                        help="silent mode, overrides existing temporary folder if was provided with --temp_folder")
    parser.add_argument('--temp_folder', default=None,
                        help="folder where to keep not zipped dumped info")
    parser.add_argument('--zip_file', default=None,
                        help="filename to be used for the final archive, can be full/relative. If not specified, default name will be used and printed on exit.")
    parser.add_argument('-c', '--include_vpp_core', nargs='?', const=3, type=int, choices=range(1, 4),
                        help="Include VPP coredumps to be part of fwdump")
    args = parser.parse_args()
    main(args)
