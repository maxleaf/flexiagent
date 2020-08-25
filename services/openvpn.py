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
import shutil
import fwglobals
import subprocess
import time
from netaddr import IPNetwork, IPAddress

class OpenVPN:
    """OpenVPN class representation.
    """
    def _install(self, params):
        """Install Open VPN server on host.
        In general, policy rules instruct VPP to route packets to specific interface,
        which is marked with multilink label that noted in policy rule.

        :param params: params - open vpn parameters:
            version - the version to installed

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
    
        try:
            if (params['version']):
                # version = params['version']
                version = 'stable'
            else:
                version = 'stable'

            os.system('mkdir -p /etc/openvpn')
            os.system('mkdir -p /etc/openvpn/server')
            os.system('mkdir -p /etc/openvpn/client')
            dir = os.path.dirname(os.path.realpath(__file__))
            shutil.copyfile('{}/openvpn_scripts/auth.sh'.format(dir), '/etc/openvpn/server/auth-script.sh')
            shutil.copyfile('{}/openvpn_scripts/up.sh'.format(dir), '/etc/openvpn/server/up-script.sh')
            shutil.copyfile('{}/openvpn_scripts/down.sh'.format(dir), '/etc/openvpn/server/down-script.sh')
        
            commands = [
                'wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg|apt-key add -',
                'echo "deb http://build.openvpn.net/debian/openvpn/%s bionic main" > /etc/apt/sources.list.d/openvpn-aptrepo.list' % version,
                'apt-get update && apt-get install -y openvpn',
                'chmod +x /etc/openvpn/server/auth-script.sh',
                'chmod +x /etc/openvpn/server/up-script.sh',
                'chmod +x /etc/openvpn/server/down-script.sh',

                # Convert DOS format to UNIX format
                "sed -i 's/\r$//' /etc/openvpn/server/auth-script.sh",
                "sed -i 's/\r$//' /etc/openvpn/server/up-script.sh",
                "sed -i 's/\r$//' /etc/openvpn/server/down-script.sh",
            
                'echo "%s" > /etc/openvpn/server/ca.key' % params['caKey'],
                'echo "%s" > /etc/openvpn/server/ca.crt' % params['caCrt'],
                'echo "%s" > /etc/openvpn/server/server.key' % params['serverKey'],
                'echo "%s" > /etc/openvpn/server/server.crt' % params['serverCrt'],
                'echo "%s" > /etc/openvpn/server/tc.key' % params['tlsKey'],
                'echo "%s" > /etc/openvpn/server/dh.pem' % params['dhKey'],

                'rm -rf ./pki'
            ]
            
            for command in commands:
                ret = os.system(command)
                if ret:
                    return (False, ret)
            
            self._modify(params)
            
            fwglobals.log.debug("Openvpn installed successfully")
            return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.
        except Exception as e:
            msg = str(e)
            fwglobals.log.error(msg)
            return (False, msg)


    def _openvpn_pid(self):
        """Get pid of OpenVpn process.

        :returns:           process identifier.
        """
        try:
            pid = subprocess.check_output(['pidof', 'openvpn'])
        except:
            pid = None
        return pid

    def _modify(self, params):
        """Configure Open VPN server on host.

        :param params: params - open vpn parameters:
            deviceWANIp - the device WAN ip
            remoteClientIp    -
            routeAllOverVpn    - false to use split tunnel

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        self._configure_server_file(params)
        self._configure_client_file(params)
        # Start the vpn server
        try:
            vpnIsRun = True if self._openvpn_pid() else False

            if (vpnIsRun):
                os.system('sudo killall openvpn')
                time.sleep(5)  # 5 sec
            
            output = os.system('sudo openvpn --config /etc/openvpn/server/server.conf --daemon')
            fwglobals.log.debug("openvpn server is running!")
            return (True, None)
        except Exception as e:
            msg = str(e)
            fwglobals.log.error(msg)
            return (False, msg)

    def _uninstall(self, params):
        """Remove Open VPN server on host.

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """

        commands = [
            'apt-get remove -y openvpn',
            'rm -rf /etc/openvpn/server/*',
            'rm -rf /etc/openvpn/client/*'
        ]

        vpnIsRun = True if self._openvpn_pid() else False

        if (vpnIsRun):
            commands.insert(0, 'killall openvpn')

        try:
            for command in commands:
                ret = os.system(command)
                if ret:
                    fwglobals.log.error(ret)
                    return (False, ret)
        except Exception as e:
            msg = str(e)
            fwglobals.log.error(msg)
            return (False, msg)

        return (True, None)

    def _upgrade(self, params):
        return self.install(params)

    def _configure_server_file(self, params):

        destFile = '/etc/openvpn/server/server.conf'
        ip = IPNetwork(params['remoteClientIp'])

        commands = [
            # Clean the file
            ' > %s' % destFile,

            # Which local IP address should OpenVPN listen on
            'echo "local %s" >> %s' % (params['deviceWANIp'], destFile),

            # Which TCP/UDP port should OpenVPN listen on?
            # 'echo "port 1194" >> %s' % destFile,

            # TCP or UDP server?
            'echo "proto udp" >> %s' % destFile,

            # "dev tun" will create a routed IP tunnel
            'echo "dev tun" >> %s' % destFile,

            # SSL/TLS root certificate
            'echo "ca /etc/openvpn/server/ca.crt" >> %s' % destFile,
            'echo "cert /etc/openvpn/server/server.crt" >> %s' % destFile,
            'echo "key /etc/openvpn/server/server.key" >> %s' % destFile,

            # Diffie hellman parameters.
            'echo "dh /etc/openvpn/server/dh.pem" >> %s' % destFile,

            # Select a cryptographic cipher.
            'echo "auth SHA512" >> %s' % destFile,

            # The server and each client must have a copy of this key
            'echo "tls-crypt /etc/openvpn/server/tc.key" >> %s' % destFile,

            # Network topology
            'echo "topology subnet" >> %s' % destFile,

            # Log
            'echo "log %s" >> %s' % (fwglobals.g.OPENVPN_LOG_FILE, destFile),

            # Configure server mode and supply a VPN subnet
            # for OpenVPN to draw client addresses from.
            'echo "server %s %s" >> %s' % (ip.ip, ip.netmask, destFile),

            # Maintain a record of client <-> virtual IP address associations in this file
            'echo "ifconfig-pool-persist /etc/openvpn/server/ipp.txt" >> %s' % destFile,

            'echo "keepalive 10 120" >> %s' % destFile,

            # Select a cryptographic cipher.
            'echo "cipher AES-256-CBC" >> %s' % destFile,
        
            #'echo "user nobody" >> %s' % destFile,
            #'echo "group nogroup" >> %s' % destFile,

            # The persist options will try to avoid ccessing certain resources on restart
            # that may no longer be accessible because of the privilege downgrade.
            'echo "persist-key" >> %s' % destFile,
            'echo "persist-tun" >> %s' % destFile,
    
            # Output a short status file showing current connections, truncated
            # and rewritten every minute.
            'echo "status /etc/openvpn/server/openvpn-status.log" >> %s' % destFile,

            # Set the appropriate level of log file verbosity.
            'echo "verb 3" >> %s' % destFile,

            # 'echo "plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /tmp/script.sh" >> %s' % destFile,
            'echo "auth-user-pass-verify /etc/openvpn/server/auth-script.sh via-file" >> %s' % destFile,
            'echo "tmp-dir /dev/shm" >> %s' % destFile,
            'echo "script-security 2" >> %s' % destFile,

            'echo "client-cert-not-required" >> %s' % destFile,
            'echo "client-config-dir /etc/openvpn/client" >> %s' % destFile,
            'echo "username-as-common-name" >> %s' % destFile,
            'echo "reneg-sec 43200" >> %s' % destFile,
            'echo "duplicate-cn" >> %s' % destFile,
            'echo "client-to-client" >> %s' % destFile,
            'echo "explicit-exit-notify" >> %s' % destFile,
            'echo "up /etc/openvpn/server/up-script.sh" >> %s' % destFile,
            'echo "down /etc/openvpn/server/down-script.sh" >> %s' % destFile
        ]

        # Split tunnel
        if params['routeAllOverVpn'] is True:
            # this directive will configure all clients to redirect their default
            # network gateway through the VPN
            commands.append('echo "push \\"redirect-gateway def1 bypass-dhcp\\"" >> %s' % destFile)        
        else:
            commands.append('echo "push \\"route 172.16.0.0 255.255.255.0\\"" >> %s' % (destFile))

        # Port
        if 'port' in params and params['port']:
            commands.append('echo "port %s" >> %s' % (params['port'], destFile))

        # DNS options
        if 'dnsIp' in params and isinstance(params['dnsIp'], list):
            for ip in params['dnsIp']:
                commands.append('echo "push \\"dhcp-option DNS %s\\"" >> %s' % (ip, destFile))

        if 'dnsName' in params and isinstance(params['dnsName'], list):
            for name in params['dnsName']:
                commands.append('echo "push \\"dhcp-option DOMAIN %s\\"" >> %s' % (name, destFile))

        for command in commands:
            ret = os.system(command)
            if ret:
                fwglobals.log.error(ret)
                return (False, ret)

        fwglobals.log.debug("Openvpn server conf configured successfully")
        return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.    

    def _configure_client_file(self, params): 

        destFile = '/etc/openvpn/client/client.conf'

        commands = [
            ' > %s' % destFile,
            'echo "client" >> %s' % destFile,
            'echo "dev tun" >> %s' % destFile,
            'echo "proto udp" >> %s' % destFile,
            'echo "remote %s" >> %s' % (params['deviceWANIp'], destFile),
            'echo "resolv-retry infinite" >> %s' % destFile,
            'echo "auth-user-pass" >> %s' % destFile,
            'echo "nobind" >> %s' % destFile,
            'echo "persist-key" >> %s' % destFile,
            'echo "persist-tun" >> %s' % destFile,
            'echo "remote-cert-tls server" >> %s' % destFile,
            'echo "auth SHA512" >> %s' % destFile,
            'echo "cipher AES-256-CBC" >> %s' % destFile,
            'echo "ignore-unknown-option block-outside-dns" >> %s' % destFile,
            'echo "block-outside-dns" >> %s' % destFile,
            'echo "verb 3" >> %s' % destFile,
            'echo "tls-client" >> %s' % destFile,
            "echo '<ca>\n' >> %s" % destFile,
            'cat /etc/openvpn/server/ca.crt >> %s' % destFile,
            "echo '</ca>\n' >> %s" % destFile,
            "echo '<tls-crypt>' >> %s" % destFile,
            'cat /etc/openvpn/server/tc.key >> %s' % destFile,
            "echo '</tls-crypt>' >> %s" % destFile
        ]

        for command in commands:
            ret = os.system(command)
            if ret:
                fwglobals.log.error(ret)
                return (False, ret)

        fwglobals.log.debug("Openvpn client conf configured successfully")
        return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.
