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

import fwglobals
import fwutils
import glob
import os
import subprocess

class FwIKEv2:
    def __init__(self):
        self.IKEV2_PRIVATE_KEY_FILE = self.private_key_filename_get()
        self.IKEV2_PUBLIC_CERTIFICATE_FILE = self.certificate_filename_get()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def initialize(self):
        return

    def finalize(self):
        return

    def private_key_filename_get(self):
        machine_id = fwutils.get_machine_id()
        private_pem = fwglobals.g.IKEV2_FOLDER + "local_key_" + machine_id + ".pem"
        return private_pem

    def certificate_filename_get(self):
        machine_id = fwutils.get_machine_id()
        public_pem = fwglobals.g.IKEV2_FOLDER + "local_certificate_" + machine_id + ".pem"
        return public_pem

    def get_certificate_expiration(self):
        '''This function retrieves local certificates expiration time.
        '''
        public_pem = self.IKEV2_PUBLIC_CERTIFICATE_FILE
        private_pem = self.IKEV2_PRIVATE_KEY_FILE

        if not os.path.exists(private_pem):
            return {'certificateExpiration': '', 'error': 'Private key is missing'}

        if not os.path.exists(public_pem):
            return {'certificateExpiration': '', 'error': 'Public key is missing'}

        cmd = "openssl x509 -enddate -noout -in %s" % public_pem
        fwglobals.log.debug(cmd)
        res = subprocess.check_output(cmd, shell=True).decode().strip()
        if not res:
            return {'certificateExpiration': '', 'error': 'No enddate for public certificate'}
        end_date = res.split('=')[1]

        cmd = "openssl rsa -check -noout -in %s" % private_pem
        fwglobals.log.debug(cmd)
        res = subprocess.check_output(cmd, shell=True).decode().strip()
        if res != "RSA key ok":
            return {'certificateExpiration': '', 'error': 'RSA key is not ok'}

        return {'certificateExpiration': end_date, 'error': ''}

    def modify_private_key(self, private_pem):
        '''This function modifies private key.
        '''
        try:
            fwglobals.g.router_api.vpp_api.vpp.api.ikev2_set_local_key(key_file=private_pem)

        except Exception as e:
            fwglobals.log.error("%s" % str(e))
            return False

        return True

    def clean(self):
        for cert in glob.glob(fwglobals.g.IKEV2_FOLDER + '/' + 'remote*.pem'):
            os.remove(cert)

    def reset(self):
        if os.path.exists(fwglobals.g.IKEV2_FOLDER):
            os.system("rm -rf %s" % fwglobals.g.IKEV2_FOLDER) # shutil.rmtree() fails sometimes on VBox shared folders!

    def create_private_key(self, days):
        machine_id = fwutils.get_machine_id()
        public_pem = self.IKEV2_PUBLIC_CERTIFICATE_FILE
        private_pem = self.IKEV2_PRIVATE_KEY_FILE

        if not os.path.exists(fwglobals.g.IKEV2_FOLDER):
            os.makedirs(fwglobals.g.IKEV2_FOLDER)

        cmd = "openssl req -new -newkey rsa:4096 -days %u -nodes -x509 -subj '/CN=%s' -keyout %s -out %s" % (days, machine_id, private_pem, public_pem)
        fwglobals.log.debug(cmd)
        ok = not subprocess.call(cmd, shell=True)
        if not ok:
            return {'ok': 0, 'message': 'Cannot create certificate'}

        with open(public_pem) as public_pem_file:
            certificate = public_pem_file.read().rstrip("\n")

        expiration = self.get_certificate_expiration()
        if expiration['error'] != '':
            return {'ok': 0, 'message': 'Cannot get certificate expiration date'}

        if fwutils.vpp_does_run():
            ok = self.modify_private_key(private_pem)
            if not ok:
                return {'ok': 0, 'message': 'Cannot set private key in VPP'}

        return {'message': {'certificate': certificate, 'expiration': expiration['certificateExpiration']}, 'ok': 1}

    def profile_name_get(self, tunnel_id):
        return 'pr' + str(tunnel_id)

    def remote_certificate_filename_get(self, machine_id):
        public_pem = fwglobals.g.IKEV2_FOLDER + "remote_certificate_" + machine_id + ".pem"
        return public_pem

    def modify_certificate(self, device_id, certificate, tunnel_id):
        '''This function modifies public certificate.
        '''
        try:
            self.add_public_certificate(device_id, certificate)
            public_pem = self.remote_certificate_filename_get(device_id)
            profile = self.profile_name_get(tunnel_id)

            fwglobals.g.router_api.vpp_api.vpp.api.ikev2_profile_set_auth(name=profile,
                                                            auth_method=1,
                                                            data=public_pem.encode(),
                                                            data_len=len(public_pem))

        except Exception as e:
            fwglobals.log.error("%s" % str(e))
            pass

    def add_public_certificate(self, device_id, certificate):
        '''This function saves public certificate as a file.

        :param device_id:   Remote device id.
        :param certificate: Certificate string.
        '''
        public_pem = self.remote_certificate_filename_get(device_id)

        if not os.path.exists(fwglobals.g.IKEV2_FOLDER):
            os.makedirs(fwglobals.g.IKEV2_FOLDER)

        with open(public_pem, 'w') as public_pem_file:
            for line in certificate:
                public_pem_file.write(line)


    def reinitiate_session(self, tunnel_id, role):
        '''This function reinitiates IKEv2 session.
        '''
        profile = self.profile_name_get(tunnel_id)

        try:
            if role == 'initiator':
                fwglobals.g.router_api.vpp_api.vpp.api.ikev2_initiate_sa_init(name=profile)

        except Exception as e:
            fwglobals.log.error("%s" % str(e))
            pass