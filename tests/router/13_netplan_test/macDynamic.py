import os
import re
import sys
import shutil
import glob
from getmac import get_mac_address as gma
import netifaces
import pdb

def macDynamic():
    """ This function will change the mac address of the respective interfaces taking the mac addresses from ifconfig 
    """
    pdb.set_trace()
    #Extracting all interfaces
    intf = netifaces.interfaces()
    #Extracting all Mac addresses
    macAds = [gma(mac) for mac in intf if mac != "lo"]
    mac = 0
    line_num = []
    net_path = '/etc/netplan/50-cloud-init.yaml'
    temp_path = '/etc/netplan/temp.yaml'
    #Changing mac addresses in netplan file
    with open(net_path) as file:
        for num, line in enumerate(file, 1):
            if 'macaddress' in line:
                line_num.append(num)
    for line in line_num:
        cmd = "sed -e '%s s/maca.*/macaddress: %s/' %s > %s && mv %s %s" % (line, macAds[mac],net_path, temp_path, temp_path, net_path)
        os.system(cmd)
	mac += 1
macDynamic()
