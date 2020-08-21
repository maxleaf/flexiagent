import pytest
import os 
import glob
import shutil

@pytest.fixture
def netplan_backup():
    orig_yaml = glob.glob("/etc/netplan/*.yaml")+ \
                glob.glob("/lib/netplan/*.yaml") + \
                glob.glob("/run/netplan/*.yaml")
    #taking backup of original netplan yaml files
    for file in orig_yaml:
        orig_backup = file.replace('yaml', 'yaml.backup')
        shutil.move(file, orig_backup)
    
    yield
    
    os.system('rm -f /etc/netplan/*.yaml')
    orig_yaml = glob.glob("/etc/netplan/*.backup")+ \
                glob.glob("/lib/netplan/*.backup") + \
                glob.glob("/run/netplan/*.backup")
    for file in orig_yaml:
        orig_backup = file.replace('yaml.backup', 'yaml')
        shutil.move(file, orig_backup)
