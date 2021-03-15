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

import datetime
import json
import filecmp
import os
import psutil
import pytest
import re
import subprocess
import sys
import time
import glob
import yaml
import traceback as tb

CODE_ROOT = os.path.realpath(__file__).replace('\\', '/').split('/tests/')[0]
TEST_ROOT = CODE_ROOT + '/tests/'
sys.path.append(CODE_ROOT)
sys.path.append(TEST_ROOT)
import fwutils

template_path = os.path.abspath(TEST_ROOT + '/fwtemplates.yaml')

class TestFwagent:
    def __init__(self):
        self.fwagent_py = 'python ' + os.path.join(CODE_ROOT, 'fwagent.py')
        self.fwkill_py  = 'python ' + os.path.join(CODE_ROOT, 'tools', 'common', 'fwkill.py')
        self.set_log_start_marker()

    def __enter__(self):
        self.clean()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.clean(traceback)

    def clean(self, traceback=None):
        os.system('systemctl stop flexiwan-router')             # Ensure there is no other instance of fwagent
        daemon_pid = fwagent_daemon_pid()
        if daemon_pid:
            os.system('kill -9 %s' % daemon_pid)                # Ensure daemon by previous failed test does not run
        if vpp_does_run():
            os.system('%s --quiet' % self.fwkill_py)            # The kill shot - ensure vpp does not run
        os.system('%s reset --soft --quiet' % self.fwagent_py)  # Clean fwagent files like persistent configuration database

        # Print exception if it is not caused by 'assert' statement
        # The 'assert' is printed by pytest.
        if traceback:
            last_frame     = tb.extract_tb(traceback)[-1]
            failed_command = last_frame[3]
            if failed_command and not re.match('assert ', failed_command):
                print("!!!! TestFwagent got exception !!!")
                lines = tb.format_tb(traceback)   # 'print_tb' output is not captured by pytest for some reason
                for l in lines:
                    print(l)

    def set_log_start_marker(self):
        self.start_time = datetime.datetime.now()
        time.sleep(1)   # Ensure that all further log times are greater than now()
                        # The now() uses microseconds, when log uses seconds only.

    def cli(self, args, daemon=False, expected_vpp_cfg=None, expected_router_cfg=None, check_log=False):
        '''Invokes fwagent API.

        :param args:   the API function name and parameters to be invoked.

        :param daemon: if True the fwagent will be created and run by background
                    process. Otherwise, the local instance of agent will be created,
                    the API will be invoked on it and the instance will be destroyed.

        :param expected_vpp_cfg: The name of the JSON file with dictionary or
                    the python list of VPP configuration items that describes
                    expected VPP configuration upon successful API invocation
                    in terms of numbers of existing objects, e.g.:
                                    {
                                        "interfaces" :  8,
                                        "tunnels":      3,
                                        "dhcp-servers": 1
                                    }
                        On API return the VPP configuration is dumped and is
                    compared to the provided dictionary. If there is no match,
                    the error is returned.

        :param expected_router_cfg: The name of the JSON file with dictionary
                    that describes expected router configuration upon successful
                    API invocation as it would be retrieved by the
                    'agent show configuration --router' command:
                                    {
                                    "======= START COMMAND =======": [
                                        {
                                        "Key": "start-router",
                                        "Params": {}
                                        }
                                    ],
                                    "======== INTERFACES ========": [
                                        {
                                        "Key": "add-interface:pci:0000:00:08.00",
                                        "Params": {
                                            "addr": "10.0.0.4/24",
                                            "gateway": "10.0.0.10",
                                            "multilink": {
                                    ...
                                    }
                    Note the router configuration is stored in the agent request
                    database file, that persists reboots and that is valid even
                    if the VPP does not run.
                        On API return the router configuration is dumped and is
                    compared to the provided dictionary. If there is no match,
                    the error is returned.

        :param check_log: if True, the log since API execution will be grepped
                    for 'error: '. If found, the error will be returned.
        '''

        if check_log:
            start_time = datetime.datetime.now()
            time.sleep(1)   # Ensure that all further log times are greater than now()
                            # The now() uses microseconds, when log uses seconds only.

        # Create instance of background fwagent if asked.
        if daemon:
            try:
                cmd = '%s daemon --dont_connect &' % (self.fwagent_py)
                os.system(cmd)

                # Poll daemon status until it becomes 'running'
                #
                timeout = 120
                cmd = '%s show --status daemon' % (self.fwagent_py)
                out = subprocess.check_output(cmd, shell=True)
                while out.strip() != 'running' and timeout > 0:
                    time.sleep(1)
                    timeout -= 1
                    out = subprocess.check_output(cmd, shell=True)
                if timeout == 0:
                    return (False, "timeout (%s seconds) on wainting for daemon to start" % (timeout))
            except Exception as e:
                return (False, "'%s' failed: %s" % (cmd, str(e)))

        # Invoke CLI.
        # If fwagent was started on background, the API command will be invoked on it.
        # If there is no fwagent in background, the local instance of it will be
        # created, API command will be run on it, and instance will be destroyed.
        #
        cmd = '%s cli %s -t %s' % (self.fwagent_py, args, template_path)
        out = subprocess.check_output(cmd, shell=True).strip()

        # Deserialize object printed by CLI onto STDOUT
        match = re.search('return-value-start (.*) return-value-end', out)
        if not match:
            return (False, { 'error': 'bad CLI output format: ' + out})
        ret = json.loads(match.group(1))
        if 'ok' in ret and ret['ok'] == 0:
            return (False, "ret=%s, out=%s" % (ret, out))

        # Ensure VPP configuration success.
        if expected_vpp_cfg:
            vpp_configured = wait_vpp_to_be_configured(expected_vpp_cfg, timeout=60)
            if not vpp_configured:
                return (False, "VPP configuration does not match %s" % expected_vpp_cfg)

        # Ensure router configuration success.
        if expected_router_cfg:
            router_configured = router_is_configured(expected_router_cfg, self.fwagent_py)
            if not router_configured:
                return (False, "router configuration does not match %s" % expected_router_cfg)

        # Ensure no errors in log.
        if check_log:
            lines = self.grep_log('error: ', since=start_time)
            if lines:
                return (False, "errors found in log: %s" % '\n'.join(lines))

        return (True, ret)


    def show(self, args):
        cmd = '%s show %s' % (self.fwagent_py, args)
        out = subprocess.check_output(cmd, shell=True)
        return out.rstrip()

    def grep_log(self, pattern, print_findings=True, since=None):
        found = []
        if not since:
            since = self.start_time

        grep_cmd = "sudo grep -a -E '%s' /var/log/flexiwan/agent.log" % pattern
        try:
            out = subprocess.check_output(grep_cmd, shell=True)
            if out:
                lines = out.splitlines()
                for (idx, line) in enumerate(lines):
                    # Jul 29 15:57:19 localhost fwagent: error: _preprocess_request: current requests: [{"message": ...
                    line_time = get_log_line_time(line)
                    line_time = line_time.replace(since.year)   # Fix year that does not present in log line
                    if line_time >= since:
                        found = lines[idx:]
                        break
                if found and print_findings:
                    for line in found:
                        print('FwTest:grep_log(%s): %s' % (pattern, line))
        except subprocess.CalledProcessError:
            pass   # 'grep' returns failure on no match!
        return found

    def wait_log_line(self, pattern, timeout=1):
        '''Periodically greps agent log for pattern until the pattern is found.

        :param pattern: the pattern for grep.
        :param timeout: how much seconds wait for pattern to appear in log.

        :returns: True on success, False if pattern was not found.
        '''
        # If 'cfg_to_check' is a file, convert it into list of tuples.
        #
        found = self.grep_log(pattern, print_findings=False)
        while not found and timeout > 0:
            time.sleep(1)
            timeout -= 1
            found = self.grep_log(pattern, print_findings=False)
        if timeout == 0:
            return False
        return True


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
        cmd = "ps -ef | egrep 'fwagent.* daemon' | grep -v grep | tr -s ' ' | cut -d ' ' -f2"
        pid = subprocess.check_output(cmd, shell=True)
    except:
        pid = None
    return pid

def linux_interfaces_count():
    cmd = 'ls -A /sys/class/net | wc -l'
    count = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).strip()
    return int(count)

def linux_interfaces_are_configured(expected_count, print_error=True):
    current = linux_interfaces_count()
    is_equal = current == expected_count
    if not is_equal and print_error:
        print("ERROR: current: %s, expected: %s" % (current, expected_count))
    return is_equal

def vpp_is_configured(config_entities, print_error=True):

    def _run_command(cmd, print_error=True):
        # This function simulates subprocess.check_output() using the Popen
        # object in order to avoid excpetions when process exits with non-zero
        # status. Otherwise pytest intercepts the exception and fails the test.
        # We need it to read output of 'vppctl' command that might exit abnormally
        # on 'clib_socket_init: connect (fd 3, '/run/vpp/cli.sock'): Connection refused' error.
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (out, _) = p.communicate()
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
            cmd          = r"sudo vppctl sh int addr | grep -E '^(loop|Gigabit|TenGigabit|vmxnet3|tapcli).* \(up\)' | wc -l"  # Don't use 'grep -c'! It exits with failure if not found!
            cmd_on_error = r"sudo vppctl sh int addr | grep -E '^(loop|Gigabit|TenGigabit|vmxnet3|tapcli).* \(up\)'"
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
    '''Fetches configuration items from the running vpp according the list of
    configuration item types provided within the 'cfg_to_check' argument,
    and compares the number of fetched items to the number of items specified
    in the 'cfg_to_check'. For example, the 'cfg_to_check' can specify
    3 interfaces and 2 tunnels. In this case this function will ensure that
    vpp runs and it has 3 interfaces in UP state and 2 tunnels.
    If no expected configuration was found, the function sleeps 1 seconds and
    retries. This is until 'timeout' seconds elapses. Then if still no expected
    configuration was found, the False is returned.

    :param cfg_to_check: list of configuration items, e.g. [('interfaces",3), ('tunnels",2)]
                    OR
                    name of JSON file with configuration, e.g. {"interfaces":3, "tunnels":2}
    :param timeout: how much seconds wait for VPP to start and to get
                    to the expected configuration.

    :returns: True on success, False if VPP has no expected configuration.
    '''
    # If 'cfg_to_check' is a file, convert it into list of tuples.
    #
    if type(cfg_to_check) == str:
        with open(cfg_to_check) as json_file:
            cfg = json.load(json_file)
            cfg_to_check = [ (key, cfg[key]) for key in cfg ]

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

def file_exists(filename, check_size=True):
    try:
        file_size_str = subprocess.check_output("sudo stat -c %%s %s 2>/dev/null" % filename, shell=True)
    except subprocess.CalledProcessError:
        return False
    if check_size and int(file_size_str.rstrip()) == 0:
        return False
    return True

def router_is_configured(expected_cfg_dump_filename,
                         fwagent_py='python /usr/share/flexiwan/agent/fwagent.py',
                         print_error=True):
    # Dumps current agent configuration into temporary file and checks
    # if the dump file is equal to the provided expected dump file.
    actual_cfg_dump_filename = expected_cfg_dump_filename + ".actual.txt"
    replaced_expected_cfg_dump_filename = expected_cfg_dump_filename + ".replaced.txt"

    dump_configuration = subprocess.check_output("sudo %s show --configuration router" % fwagent_py, shell=True)
    dump_multilink = subprocess.check_output("sudo %s show --configuration multilink-policy" % fwagent_py, shell=True)
    dump_system = subprocess.check_output("sudo %s show --configuration system" % fwagent_py, shell=True)

    actual_json = json.loads(dump_configuration)
    if dump_multilink.strip():
        actual_json.update(json.loads(dump_multilink))
    if dump_system.strip():
        actual_json.update(json.loads(dump_system))

    expected_json = fwutils.replace_file_variables(template_path, expected_cfg_dump_filename)

    actual_json_dump = json.dumps(actual_json, indent=2, sort_keys=True)
    expected_json_dump = json.dumps(expected_json, indent=2, sort_keys=True)

    ok = actual_json_dump == expected_json_dump
    if ok:
        if os.path.exists(actual_cfg_dump_filename):
            os.remove(actual_cfg_dump_filename)
        if os.path.exists(replaced_expected_cfg_dump_filename):
            os.remove(replaced_expected_cfg_dump_filename)
    else:
        with open(actual_cfg_dump_filename, 'w+') as f:
            f.write(actual_json_dump)
        with open(replaced_expected_cfg_dump_filename, 'w+') as f:
            f.write(expected_json_dump)
        if print_error:
            print("ERROR: %s does not match %s" % (replaced_expected_cfg_dump_filename, actual_cfg_dump_filename))
    return ok

def get_log_line_time(log_line):
    # Jul 29 15:57:19 localhost fwagent: error: _preprocess_request: current requests: [{"message": ...
    tokens = log_line.split()[0:3]
    if not tokens:
        tokens = ["Jan", "01", "00:00:01"]
    if len(tokens[1]) == 1:  # Add zero padding to single digit day of month
        log_time = "%s 0%s %s" % (tokens[0], tokens[1], tokens[2])
    else:
        log_time = "%s %s %s" % (tokens[0], tokens[1], tokens[2])
    return datetime.datetime.strptime(log_time, '%b %d %H:%M:%S')

def adjust_environment_variables():
    '''
    This function replaces the netplan files variables and macaddr with the actual macaddr
    '''
    netplan_paths = glob.glob('/etc/netplan/*.yaml')
    #Changing mac addresses in all netplan files
    #Copy the current yaml into json variable, change the mac addr
    #Copy the coverted json string back to yaml file
    data = fwutils.get_template_data_by_hw(template_path)

    intf_mac_addr = {}
    interfaces = psutil.net_if_addrs()
    for nicname, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                intf_mac_addr[nicname] = addr.address
    for netplan in netplan_paths:
        with open(netplan, "r+") as fd:
            netplan_json = yaml.load(fd)
            for if_name, val in netplan_json['network']['ethernets'].items():
                replaced_name = str(data[if_name.split('name')[0]]['name'])
                netplan_json['network']['ethernets'][replaced_name] = netplan_json['network']['ethernets'].pop(if_name)
                interface = netplan_json['network']['ethernets'][replaced_name]
                if interface.get('match'):
                    interface['match']['macaddress'] = intf_mac_addr[replaced_name]
                if interface.get('set-name'):
                    interface['set-name'] = replaced_name
            netplan_str = yaml.dump(netplan_json)
            fd.seek(0)
            fd.write(netplan_str)
            fd.truncate()