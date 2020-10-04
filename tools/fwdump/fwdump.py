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


# This script collects various information about FlexiWAN Edge device, e.g.
# configuration of router, fwagent logs, interface configuration in Linux, etc.
# Every piece of data is dumped into dedicated file in temporary folder,
# than whole folder is tar-ed and is zipped.


import datetime
import getopt
import os
import re
import shutil
import subprocess
import sys
import time

# Special variables in the dumper commands are substituted in run time as follows:
#   <dumper_out_file> -> '<temporary_folder>/<dumper>.log'
#   <temp_folder>     -> current folder or --temp_folder script argument

g_dumpers = {
    'linux_interfaces':             { 'shell_cmd': 'ip addr > <dumper_out_file>' },
    'linux_routes':                 { 'shell_cmd': 'ip route > <dumper_out_file>' },
    'linux_neighbors':              { 'shell_cmd': 'ip neigh > <dumper_out_file>' },
    'linux_pidof_vpp':              { 'shell_cmd': 'echo "vpp: $(pidof vpp)" > <dumper_out_file>; echo "vppctl: $(pidof vppctl)" >> <dumper_out_file>; ps -elf | grep vpp >> <dumper_out_file>' },

    'fwagent_log':                  { 'shell_cmd': 'cp /var/log/flexiwan/agent.log <temp_folder>/ ; cp /var/log/flexiwan/agent.log.1 <temp_folder>/' },
    'fwagent_router_cfg':           { 'shell_cmd': 'fwagent show --router configuration > <dumper_out_file>' },
    'fwagent_multilink_cfg':        { 'shell_cmd': 'fwagent show --router multilink-policy > <dumper_out_file>' },

    'vpp_interfaces_hw':            { 'shell_cmd': 'vppctl sh hard > <dumper_out_file>' },
    'vpp_interfaces_sw':            { 'shell_cmd': 'vppctl sh int > <dumper_out_file>' },
    'vpp_interfaces_addresses':     { 'shell_cmd': 'vppctl sh int addr > <dumper_out_file>' },
    'vpp_fwabf_labels':             { 'shell_cmd': 'vppctl sh fwabf label > <dumper_out_file>' },
    'vpp_fwabf_links':              { 'shell_cmd': 'vppctl sh fwabf link > <dumper_out_file>' },
    'vpp_fwabf_policies':           { 'shell_cmd': 'vppctl sh fwabf policy > <dumper_out_file>' },
    'vpp_fwabf_attachments':        { 'shell_cmd': 'vppctl sh fwabf attach > <dumper_out_file>' },
    'vpp_fib_entries':              { 'shell_cmd': 'vppctl sh fib entry > <dumper_out_file>' },
    'vpp_fib_paths':                { 'shell_cmd': 'vppctl sh fib paths > <dumper_out_file>' },
    'vpp_fib_pathlists':            { 'shell_cmd': 'vppctl sh fib path-lists > <dumper_out_file>' },
    'vpp_acl_dump':                 { 'shell_cmd': 'echo acl_dump > vat.txt && vpp_api_test script in vat.txt > <dumper_out_file> 2>&1 ; rm -rf vat.txt' }
}

class FwDump:
    def __init__(self, temp_folder=None, quiet=False):

        self.temp_folder    = temp_folder
        self.quiet          = quiet
        self.prompt         = 'fwdump>> '
        self.zip_file       = None

        self.now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if not temp_folder:
            self.temp_folder = os.path.join(os.getcwd(), self.now)

        # Create temporary folder
        #
        if os.path.exists(self.temp_folder):
            if self.quiet:
                shutil.rmtree(self.temp_folder)
                time.sleep(1)  # Give system a time to remove fd
                os.mkdir(self.temp_folder)
            else:
                choice = raw_input(self.prompt + "the temporary folder '%s' exists, overwrite? [Y/n]: " % self.temp_folder)
                if choice == 'y' or choice == 'Y' or choice == '':
                    shutil.rmtree(self.temp_folder)
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
            shutil.rmtree(self.temp_folder)

    def _dump(self, dumpers):
        '''Run dumpers provided by the 'dumpers' list argument.
        The list contains names of dumpers that serve as keys for the global
        g_dumpers map.
        '''
        try:
            vpp_pid = subprocess.check_output(['pidof', 'vpp'])
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
                    print(self.prompt + 'ERROR: %s: "%s" failed: %s' % (dumper, cmd, str(e)))
                    continue

    def zip(self, filename=None, delete_temp_folder=True):
        if not filename:
            filename = 'fwdump_%s.tar.gz' % self.now
        self.zip_file = filename
        cmd = 'tar -zcf %s -C %s .' % (self.zip_file, self.temp_folder)
        try:
            subprocess.check_call(cmd, shell=True)
        except Exception as e:
            print(self.prompt + 'ERROR: "%s" failed: %s' % (cmd, str(e)))

    def dump_all(self):
        dumpers = g_dumpers.keys()
        self._dump(dumpers)

    def dump_multilink(self):
        dumpers = [
                    'linux_interfaces',
                    'linux_routes',
                    'linux_neighbors',
                    'linux_pidof_vpp',
                    'fwagent_log',
                    'fwagent_router_cfg',
                    'fwagent_multilink_cfg',
                    'vpp_interfaces_hw',
                    'vpp_interfaces_sw',
                    'vpp_interfaces_addresses',
                    'vpp_fwabf_labels',
                    'vpp_fwabf_links',
                    'vpp_fwabf_policies',
                    'vpp_fwabf_attachments',
                    'vpp_fib_entries',
                    'vpp_fib_paths',
                    'vpp_fib_pathlists'
                    ]
        self._dump(dumpers)

def main(args):
    with FwDump(temp_folder=args.temp_folder, quiet=args.quiet) as dump:

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
            dump.zip(filename=args.zip_file)
            print('Done: %s' % dump.zip_file)
        else:
            print('Done, result are here: %s' % dump.temp_folder)


if __name__ == '__main__':
    import argparse
    global arg

    parser = argparse.ArgumentParser(description='FlexiEdge dump utility')
    parser.add_argument('--feature', choices=['multilink'], default=None,
                        help="dump info related to this feature only")
    parser.add_argument('--zip_file', default=None,
                        help="filename to be used for the final tar.gz archive, can be full/relative/no path")
    parser.add_argument('--dont_zip', action='store_true',
                        help="filename to be used for the final tar.gz archive, can be full/relative/no path")
    parser.add_argument('--temp_folder', default=None,
                        help="folder where to keep not zipped dumped info")
    parser.add_argument('-q', '--quiet', action='store_true',
                        help="if you want shoot - shoot, don't talk")
    args = parser.parse_args()
    main(args)
