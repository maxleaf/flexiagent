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

import os
import psutil
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
        out = subprocess.check_output(cmd, shell=True)
        ok = False if re.search('\bError\b|\berror\b|"ok"[ ]+:[ ]+0', out) else True
        if not ok and print_output_on_error:
            print("TestFwagent::cli: FAILURE REPORT START")
            print("TestFwagent::cli: command: '%s'" % cmd)
            print("TestFwagent::cli: output:")
            print(out)
            print("TestFwagent::cli: FAILURE REPORT END")
        return (ok, out)

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

    def _check_command_output(cmd, descr='', print_error=True):
        out = subprocess.check_output(cmd, shell=True).rstrip()
        if out != str(amount):
            if print_error:
                print("ERROR: number %s doesn't match: expected %d, found %s" % (descr, amount, out))
                print("ERROR: cmd=%s" % (cmd))
                print("ERROR: out=%s" % (out))
            return False
        return True

    for (e, amount) in config_entities:
        if e == 'interfaces':
            # Count number of interfaces that are UP
            cmd = r"sudo vppctl sh int addr | grep -E '^(loop|Gigabit).* \(up\)' | wc -l"  # Don't use 'grep -c'! It exits with failure of not found!
            if not _check_command_output(cmd, 'UP interfaces'):
                out = subprocess.check_output(r"sudo vppctl sh int addr | grep -E '^(loop|Gigabit).* \(up\)'", shell=True).rstrip()
                print("ERROR:\n" + out)
                return False
        if e == 'tunnels':
            # Count number of existing tunnel
            # Firstly try ipsec gre tunnels. If not found, try the vxlan tunnels.
            cmd = "sudo vppctl sh ipsec gre tunnel | grep src | wc -l"
            if not _check_command_output(cmd, 'tunnels', print_error=False):
                cmd = "sudo vppctl show vxlan tunnel | grep src | wc -l"
                if not _check_command_output(cmd, 'tunnels', print_error):
                    out_ipsec = subprocess.check_output("sudo vppctl sh ipsec gre tunnel", shell=True).rstrip()
                    out_vxlan = subprocess.check_output("sudo vppctl show vxlan tunnel", shell=True).rstrip()
                    print("ERROR:\n" + out_ipsec + "\n" + out_vxlan)
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
    # Wait for vpp to be ready tp process cli requests
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
