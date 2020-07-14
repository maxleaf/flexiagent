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
import filecmp
import os
import psutil
import pytest
import re
import subprocess
import sys
import time
import traceback as tb

class TestFwagent:
    def __init__(self):
        code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
        self.fwagent_py = 'python ' + os.path.join(code_root, 'fwagent.py')
        self.daemon_pid = None

    def __enter__(self):
        os.system('systemctl stop flexiwan-router')     # Ensure there is no other instance of fwagent
        os.system('%s reset --soft' % self.fwagent_py)  # Clean fwagent files like persistent configuration database
        if vpp_does_run():
            os.system('%s stop' % self.fwagent_py)          # Stop vpp and restore interfaces back to Linux
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        if self.daemon_pid:
            os.system('kill -9 %s' % self.daemon_pid)   # Kill daemon if runs
        os.system('%s reset --soft' % self.fwagent_py)  # Clean fwagent files like persistent configuration database
        if vpp_does_run():
            if traceback:
                print("!!!! TestFwagent got exception !!!")
                tb.print_tb(traceback)
            os.system('%s stop' % self.fwagent_py)          # Stop vpp and restore interfaces back to Linux


    def cli(self, args, daemon=False, print_output_on_error=True):

        # Create instance of background fwagent if asked.
        if daemon:
            cmd = '%s daemon --dont_connect &' % (self.fwagent_py)
            try:
                os.system(cmd)
                self.daemon_pid = fwagent_daemon_pid()
                time.sleep(1)  # Give a second to fwagent to be initialized
            except Exception as e:
                return (False, "'%s' failed: %s" % (cmd, str(e)))

        # Invoke CLI.
        # If fwagent was started on background, the API command will be invoked on it.
        # If there is no fwagent in background, the local instance of it will be
        # created, API command will be run on it, and instance will be destroyed.
        #
        cmd = '%s cli %s' % (self.fwagent_py, args)
        out = subprocess.check_output(cmd, shell=True).strip()

        # Deserialize object printed by CLI onto STDOUT
        match = re.search('return-value-start (.*) return-value-end', out)
        if not match:
            print("TestFwagent::cli: BAD OUTPUT START")
            print("TestFwagent::cli: command: '%s'" % cmd)
            print("TestFwagent::cli: output:")
            print(out)
            print("TestFwagent::cli: BAD OUTPUT END")
            return (False, { 'error': 'bad CLI output format'})
        ret = json.loads(match.group(1))
        if 'ok' in ret and ret['ok'] == 0:
            ok = False
            if print_output_on_error:
                print("TestFwagent::cli: FAILURE REPORT START")
                print("TestFwagent::cli: command: '%s'" % cmd)
                print("TestFwagent::cli: error:   '%s'" % ret['error'])
                print("TestFwagent::cli: output:")
                print(out)
                print("TestFwagent::cli: FAILURE REPORT END")
        else:
            ok = True

        return (ok, ret)

    def show(self, args):
        cmd = '%s show %s' % (self.fwagent_py, args)
        out = subprocess.check_output(cmd, shell=True)
        return out.rstrip()

def vpp_does_run():
    runs = True if vpp_pid() else False
    return runs

def vpp_pid():
    try:
        pid = subprocess.check_output(['pidof', 'vpp'])
    except:
        pid = None
    return pid

def fwagent_daemon_pid():
    try:
        cmd = "ps -ef | grep 'fwagent daemon' | grep -v grep | tr -s ' ' | cut -d ' ' -f2"
        pid = subprocess.check_output(cmd, shell=True)
    except:
        pid = None
    return pid

def vpp_is_configured(config_entities, print_error=True):

    def _run_command(cmd, print_error=True):
        # This function simulates subprocess.check_output() using the Popen
        # object in order to avoid excpetions when process exits with non-zero
        # status. Otherwise pytest intercepts the exception and fails the test.
        # We need it to read output of 'vppctl' command that might exit abnormally
        # on 'clib_socket_init: connect (fd 3, '/run/vpp/cli.sock'): Connection refused' error.
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (out, unused_err) = p.communicate()
        retcode = p.poll()
        return (retcode, out.rstrip())

    def _check_command_output(cmd, expected_out, descr='', cmd_on_error=None, print_error=True):
        # Can't use 'subprocess.check_output' as it raises exception on non-zero return code
        # due to 'clib_socket_init: connect (fd 3, '/run/vpp/cli.sock'): Connection refused' error.
        # Use Popen instead and collect output using communicate() method.
        (retcode, out) = _run_command(cmd)
        if retcode != 0 or out != expected_out:
            if print_error:
                if retcode != 0:
                    print("ERROR: cmd=%s: exit code=%s" % (cmd, str(retcode)))
                else:
                    print("ERROR: number %s doesn't match: expected %s, found %s" % (descr, expected_out, out))
                    print("ERROR: cmd=%s" % (cmd))
                    print("ERROR: out=%s" % (out))
                    if cmd_on_error:
                        (retcode, out) = _run_command(cmd_on_error)
                        print("ERROR: (%s):\n%s" % (cmd_on_error, str(out)))
            return False
        return True

    for (e, amount) in config_entities:
        output = str(amount)
        if e == 'interfaces':
            # Count number of interfaces that are UP
            cmd          = r"sudo vppctl sh int addr | grep -E '^(loop|Gigabit).* \(up\)' | wc -l"  # Don't use 'grep -c'! It exits with failure of not found!
            cmd_on_error = r"sudo vppctl sh int addr | grep -E '^(loop|Gigabit).* \(up\)'"
            if not _check_command_output(cmd, output, 'UP interfaces', cmd_on_error, print_error):
                return False
        if e == 'tunnels':
            # Count number of existing tunnel
            # Firstly try ipsec gre tunnels. If not found, try the vxlan tunnels.
            cmd          = "sudo vppctl sh ipsec gre tunnel | grep src | wc -l"
            cmd_on_error = "sudo vppctl sh ipsec gre tunnel"
            if not _check_command_output(cmd, output, 'tunnels', cmd_on_error, print_error):
                cmd          = "sudo vppctl show vxlan tunnel | grep src | wc -l"
                cmd_on_error = "sudo vppctl show vxlan tunnel"
                if not _check_command_output(cmd, output, 'tunnels', cmd_on_error, print_error) and print_error:
                    return False
        if e == 'applications':
            # Not supported yet - applications are relfected in VPP ACL,
            # but the relation between number of applications and ACL rules
            # is not linear.
            continue
        if e == 'multilink-policies':
            # Count number of existing tunnel
            # Firstly try ipsec gre tunnels. If not found, try the vxlan tunnels.
            cmd          = "sudo vppctl show fwabf policy | grep fwabf: | wc -l"
            cmd_on_error = "sudo vppctl show fwabf policy"
            if not _check_command_output(cmd, output, 'multilink-policies', cmd_on_error, print_error):
                return False
        if e == 'dhcp-servers':
            # Count number of existing tunnel
            # Firstly try ipsec gre tunnels. If not found, try the vxlan tunnels.
            cmd          = "sudo grep -E '^subnet [0-9.]+ netmask' /etc/dhcp/dhcpd.conf | wc -l"
            cmd_on_error = "sudo cat /etc/dhcp/dhcpd.conf"
            if not _check_command_output(cmd, output, 'dhcp-servers', cmd_on_error, print_error):
                return False
    return True


def wait_vpp_to_start(timeout=1000000):
    # Wait for vpp process to be spawned
    pid = vpp_pid()
    while not pid and timeout > 0:
        time.sleep(1)
        timeout -= 1
        pid = vpp_pid()
    if timeout == 0:
        return False
    # Wait for vpp to be ready to process cli requests
    res = subprocess.call("sudo vppctl sh version", shell=True)
    while res != 0 and timeout > 0:
        time.sleep(3)
        timeout -= 1
        res = subprocess.call("sudo vppctl sh version", shell=True)
    if timeout == 0:
        return False
    return True

def wait_vpp_to_be_configured(cfg_to_check, timeout=1000000):
    to = timeout
    configured = vpp_is_configured(cfg_to_check, print_error=False)
    while not configured and timeout > 0:
        time.sleep(1)
        timeout -= 1
        configured = vpp_is_configured(cfg_to_check, print_error=False)
    if timeout == 0:
        print("ERROR: wait_vpp_to_be_configured: return on timeout (%s)" % str(to))
        configured = False
    if not configured:  # If failed - run again, this time with print_error=True
        configured = vpp_is_configured(cfg_to_check, print_error=True)
    return configured


def wait_fwagent_exit(timeout=1000000):
    for p in psutil.process_iter(attrs=['pid', 'cmdline']):
        found = [True for cmd_arg in p.info['cmdline'] if 'fwagent.py' in cmd_arg]
        if found:
            p.terminate()
            (_, alive) = psutil.wait_procs([p], timeout=timeout)
            for p in alive:
                p.kill()
                print("ERROR: wait_fwagent_exit: return on timeout (%s): %s" % (str(timeout), p.info['pid']))
                return False
    return True


def router_is_configured(expected_cfg_dump_filename, print_error=True):
    # Dumps current agent configuration into temporary file and checks
    # if the dump file is equal to the provided expected dump file.
    actual_cfg_dump_filename = expected_cfg_dump_filename + ".actual.txt"
    dump_configuration_cmd = "sudo fwagent show --router configuration > %s" % actual_cfg_dump_filename
    subprocess.call(dump_configuration_cmd, shell=True)
    dump_multilink_cmd = "sudo fwagent show --router multilink-policy >> %s" % actual_cfg_dump_filename
    subprocess.call(dump_multilink_cmd, shell=True)
    ok = filecmp.cmp(expected_cfg_dump_filename, actual_cfg_dump_filename)
    if ok:
        os.remove(actual_cfg_dump_filename)
    elif print_error:
        print("ERROR: %s does not match %s" % (expected_cfg_dump_filename, actual_cfg_dump_filename))
    return ok

def file_exists(filename, check_size=True):
    try:
        file_size_str = subprocess.check_output("sudo stat -c %%s %s" % filename, shell=True)
    except subprocess.CalledProcessError:
        return False
    if check_size and int(file_size_str.rstrip()) == 0:
        return False
    return True

