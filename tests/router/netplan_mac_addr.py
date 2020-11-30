'''
This file corrects the netplan files with the actual interface's macaddr
'''
import glob
import os
import re
import subprocess
import shlex
import json
import yaml

def convert_netplan_macaddr():
    '''
     This function replaces the netplan files macaddr with the actual macaddr
    '''
    netplan_paths = glob.glob('/etc/netplan/*.yaml')
    #Changing mac addresses in all netplan files
    #Copy the current yaml into json file, change the mac addr
    #Remove the existing netplan and convert json file back to yaml
    for netplan in netplan_paths:
        with open("netplan.json", "w") as json_fd:
            with open(netplan) as yaml_fd:
                netplan_json = yaml.load(yaml_fd)
                for intf in netplan_json['network']['ethernets']:
                    if netplan_json['network']['ethernets'][intf].get('match'):
                        cmd = 'ip addr show %s' %intf
                        conn = subprocess.Popen(shlex.split(cmd),
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE)
                        res, _ = conn.communicate()
                        mac_str = re.search('ether ([a-z0-9:]*) ', res)
                        mac = mac_str.group(1)
                        netplan_json['network']['ethernets'][intf]['match']['macaddress'] = mac
                json.dump(netplan_json, json_fd)
            os.system('rm -rf netplan')
        with open(netplan, 'w') as yaml_fd, open("netplan.json", "r") as json_fd:
            yaml.safe_dump(json.load(json_fd), yaml_fd, encoding='utf-8', allow_unicode=True)
        os.system('rm -rf netplan.json')
