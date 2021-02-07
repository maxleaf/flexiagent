import glob
import os
import re
import sys
import shutil
import glob
from getmac import get_mac_address as gma
import netifaces

def convertMacAddress():
    """ This function will change the mac address of the respective interfaces taking the mac addresses from ifconfig 
    """
    #Extracting all interfaces
    intf = netifaces.interfaces()
    #Extracting all Mac addresses
    macAds = [gma(mac) for mac in intf if mac != "lo"]
    mac = 0
    line_num = []
    net_paths = glob.glob('/etc/netplan/*.yaml')
    temp_path = '/etc/netplan/temp.yaml'
    #Changing mac addresses in netplan file
    for net_path in net_paths:
        with open(net_path) as file:
            for num, line in enumerate(file, 1):
                if 'macaddress' in line:
                    line_num.append(num)
        for line in line_num:
            cmd = "sed -e '%s s/maca.*/macaddress: %s/' %s > %s && mv %s %s" % (line, macAds[mac],net_path, temp_path, temp_path, net_path)
            os.system(cmd)
            mac += 1

convertMacAddress()
