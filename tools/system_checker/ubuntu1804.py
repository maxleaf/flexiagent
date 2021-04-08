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


import os
import re
import subprocess

import fwsystem_checker_common

class Checker(fwsystem_checker_common.Checker):
    """This is Checker class representation.
    """
    def soft_check_resolvconf(self, fix=False, silently=False, prompt=None):
        """Check if resolvconf is installed.

        :param fix:             Install resolvconf.
        :param silently:        Run silently.
        :param prompt:          Ask user for prompt.

        :returns: 'True' if it resolvconf is installed, 'False' otherwise.
        """
        installed = False
        config_filename = '/etc/resolvconf/resolv.conf.d/tail'
        try: # Refresh self.nameservers on every invocation
            out = subprocess.check_output("grep '^nameserver ' %s" % config_filename, shell=True).decode().strip().split('\n')
            self.nameservers = [ line.split(' ')[1] for line in out ]  # 'line' format is 'nameserver 127.0.0.53'
        except:
            self.nameservers = []

        try:
            out = subprocess.check_output('dpkg -l | grep resolvconf', shell=True).strip()
            if len(out) == 0:
                raise Exception(prompt + 'resolvconf is not installed')
            else:
                installed = True
            # The resolvconf is installed now , ensure that it is configured with DNS servers
            if len(self.nameservers) == 0:
                raise Exception('no name servers was found in %s' % config_filename)
            return True
        except:
            if not fix:
                return False
            else:
                if silently:
                    # Install the daemon if not installed
                    if not installed:
                        os.system('apt-get update > /dev/null 2>&1')
                        ret = os.system('apt -y install resolvconf > /dev/null 2>&1')
                        if ret != 0:
                            print(prompt + 'failed to install resolvconf')
                            return False
                    # Now add the 8.8.8.8 to it's configuration
                    if len(self.nameservers) == 0:
                        ret = os.system('printf "\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n" >> %s' % config_filename)
                        if ret != 0:
                            print(prompt + 'failed to add 8.8.8.8 to %s' % config_filename)
                            return False
                        os.system('systemctl restart resolvconf > /dev/null 2>&1')
                        return True
                else:
                    # Install the daemon if not installed
                    if not installed:
                        choice = input(prompt + "download and install resolvconf? [Y/n]: ")
                        if choice == 'y' or choice == 'Y' or choice == '':
                            os.system('apt-get update')
                            ret = os.system('apt -y install resolvconf')
                            if ret != 0:
                                print(prompt + 'failed to install resolvconf')
                                return False
                        else:
                            return False
                    # Now add DNS servers to it's configuration, if no servers present
                    if len(self.nameservers) == 0:
                        while True:
                            server = input(prompt + "enter DNS Server address, e.g. 8.8.8.8: ")
                            ret = os.system('printf "nameserver %s\n" >> %s' % (server, config_filename))
                            ret_str = 'succeeded' if ret == 0 else 'failed'
                            print(prompt + ret_str + ' to add ' + server)
                            choice = input(prompt + "repeat? [y/N]: " )
                            if choice == 'y' or choice == 'Y':
                                continue
                            elif choice == 'n' or choice == 'N' or choice == '':
                                break
                        os.system('systemctl restart resolvconf > /dev/null 2>&1')
                        return True if ret == 0 else False
                    return True

    def _is_service_active(self, service):
        """Return True if service is running"""
        cmd = '/bin/systemctl status %s.service' % service
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        lines = proc.communicate()[0].decode().split('\n')
        for line in lines:
            if 'Active:' in line:
                if '(running)' in line:
                    return True
        return False

    def _start_service(self, service):
        """Return True if service is started"""
        os.system('/bin/systemctl unmask %s.service > /dev/null 2>&1' % service)
        os.system('/bin/systemctl enable %s.service > /dev/null 2>&1' % service)
        os.system('/bin/systemctl start %s.service > /dev/null 2>&1' % service)
        return True

    def soft_check_networkd(self, fix=False, silently=False, prompt=None):
        """Check if networkd is running.

        :param fix:             Run networkd.
        :param silently:        Run silently.
        :param prompt:          Ask user for prompt.

        :returns: 'True' if it networkd is running, 'False' otherwise.
        """
        running = False
        try:
            running = self._is_service_active("systemd-networkd")
            if running == False:
                raise Exception(prompt + 'networkd is not running')
            else:
                running = True
            return True
        except Exception as e:
            print(prompt + str(e))
            if not fix:
                return False
            else:
                if silently:
                    # Run the daemon if not running
                    if not running:
                        ret = self._start_service("systemd-networkd")
                        if not ret:
                            print(prompt + 'failed to start networkd')
                            return ret
                    return True
                else:
                    # Run the daemon if not running
                    if not running:
                        choice = input(prompt + "start networkd? [Y/n]: ")
                        if choice == 'y' or choice == 'Y' or choice == '':
                            ret = self._start_service("systemd-networkd")
                            if not ret:
                                print(prompt + 'failed to start networkd')
                                return ret
                            return True
                        else:
                            return False

    def soft_check_disable_linux_autoupgrade(self, fix=False, silently=False, prompt=None):
        """Check if Linux autoupgrade is disabled.

        :param fix:             Disable autoupgrade.
        :param silently:        Run silently.
        :param prompt:          Ask user for prompt.

        :returns: 'True' if it autoupgrade is disabled, 'False' otherwise.
        """
        autoupgrade_file   = '/etc/apt/apt.conf.d/20auto-upgrades'
        autoupgrade_params = [
            'APT::Periodic::Update-Package-Lists',
            'APT::Periodic::Unattended-Upgrade'
        ]

        def _fetch_autoupgrade_param(param):
            try:
                out = subprocess.check_output("grep '%s' %s " % (param, autoupgrade_file) , shell=True).decode().strip().split('\n')[0]
                # APT::Periodic::Update-Package-Lists "0";
                m = re.search(' "(.)";', out)
                if m:
                    enabled = True if int(m.group(1)) else False
                    return enabled
                raise Exception("not supported format in %s (out=%s)" % (autoupgrade_file, out))
            except subprocess.CalledProcessError:
                raise Exception("not found")
            return False

        def _set_autoupgrade_param(param, val):
            # Firstly remove parameter from file if exist.
            # Than add the parameter as a new line.
            # Example of line in file: APT::Periodic::Update-Package-Lists "0";
            os.system('sed -i -E "/%s /d" %s' % (param, autoupgrade_file))
            os.system('printf "%s \\"%s\\";\n" >> %s' % (param, str(val), autoupgrade_file))

        # Firstly ensure that autoupgrade configuration file exists.
        # If it doesn't exist, create it.
        #
        if not os.path.isfile(autoupgrade_file):
            if not fix:
                print(prompt + '%s not found' % autoupgrade_file)
                return False
            else:
                os.system('touch ' + autoupgrade_file)

        # Check if there is a least one parameter that should be fixed
        params_to_fix = []
        for param in autoupgrade_params:
            try:
                enabled = _fetch_autoupgrade_param(param)
                if enabled:
                    params_to_fix.append({'name': param, 'status': 'enabled'})
            except Exception as e:
                params_to_fix.append({'name': param, 'status': str(e)})
        if len(params_to_fix) == 0:
            return True

        # Fix parameter if needed
        if not fix:
            for param in params_to_fix:
                print(prompt + '%s %s' % (param['name'], param['status']))
            return False
        else:
            succeeded = True
            for param in params_to_fix:
                try:
                    _set_autoupgrade_param(param['name'], 0)
                except Exception as e:
                    print(prompt + 'failed to disable %s: %s' % (param['name'], str(e)))
                    succeeded = False
            return succeeded


    def soft_check_utc_timezone(self, fix=False, silently=False, prompt=None):
        """Check if UTC zone is configured.

        :param fix:             Configure UTC zone.
        :param silently:        Run silently.
        :param prompt:          Ask user for prompt.

        :returns: 'True' if it UTC zone is configured, 'False' otherwise.
        """
        #>> timedatectl
        #          Local time: Wed 2019-10-30 17:22:24 UTC
        #      Universal time: Wed 2019-10-30 17:22:24 UTC
        #            RTC time: Wed 2019-10-30 17:22:24
        #           Time zone: Etc/UTC (UTC, +0000)
        # System clock synchronized: no
        # systemd-timesyncd.service active: yes
        #     RTC in local TZ: no
        try:
            out = subprocess.check_output("timedatectl | grep 'Time zone:'", shell=True).decode().strip()
        except Exception as e:
            print(prompt + str(e))
            return False
        if 'Time zone: Etc/UTC' in out or 'Time zone: UTC' in out:
            return True

        if not fix:
            print(prompt + 'time zone is not UTC: ' + out)
            return False

        ret = os.system('timedatectl set-timezone UTC')
        if ret != 0:
            return False
        return True
