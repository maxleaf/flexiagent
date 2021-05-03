#!/bin/env python3


import os
import fnmatch
import time
from vpp_papi import VPP

def papi_event_handler(msgname, result):
    print(msgname)
    print(result)
 
vpp_json_dir = '/usr/share/vpp/api/'
 
jsonfiles = []
for root, dirnames, filenames in os.walk(vpp_json_dir):
    for filename in fnmatch.filter(filenames, '*.api.json'):
        jsonfiles.append(os.path.join(vpp_json_dir, filename))
 
if not jsonfiles:
    print('Error: no json api files found')
    exit(-1)

print('Connecting to VPP...')

vpp = VPP(jsonfiles)
r = vpp.connect('papi-example')

rv = vpp.api.show_version()
print('VPP version =', rv.version.decode().rstrip('\0x00'))

print('Interfaces:')
for intf in vpp.api.sw_interface_dump():
    print(' - ' + intf.interface_name.decode())

r = vpp.disconnect()
exit(r)
