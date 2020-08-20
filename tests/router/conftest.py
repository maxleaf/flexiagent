import pytest
import os 
import glob
import shutil

@pytest.fixture
def netplan_backup():
    orig_yaml = glob.glob("/etc/netplan/*.yaml")+ \
                glob.glob("/lib/netplan/*.yaml") + \
                glob.glob("/run/netplan/*.yaml")
    #taking backup of original netplan yaml file
    orig_backup = orig_yaml[0].replace('yaml', 'yaml.backup')
    shutil.move(orig_yaml[0], orig_backup)
    
    yield
    
    os.system('rm -f /etc/netplan/*.yaml')
    orig_yaml = glob.glob("/etc/netplan/*.backup")+ \
                glob.glob("/lib/netplan/*.backup") + \
                glob.glob("/run/netplan/*.backup")
    if orig_yaml:
        orig_backup = orig_yaml[0].replace('yaml.backup', 'yaml')
        shutil.move(orig_yaml[0], orig_backup)