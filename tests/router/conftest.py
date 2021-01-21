import pytest
import os 
import glob
import shutil
from datetime import datetime

@pytest.fixture
def netplan_backup():
    orig_yamls = glob.glob("/etc/netplan/*.yaml")+ \
                glob.glob("/lib/netplan/*.yaml") + \
                glob.glob("/run/netplan/*.yaml")
    #taking backup of original netplan yaml files
    for file in orig_yamls:
        orig_yaml = file.replace('yaml', 'yaml.backup_pytest')
        shutil.move(file, orig_yaml)
    
    yield
    
    os.system('rm -f /etc/netplan/*.yaml')
    orig_yamls = glob.glob("/etc/netplan/*.backup_pytest")+ \
                glob.glob("/lib/netplan/*.backup_pytest") + \
                glob.glob("/run/netplan/*.backup_pytest")
    for file in orig_yamls:
        orig_yaml = file.replace('yaml.backup_pytest', 'yaml')
        shutil.move(file, orig_yaml)
    os.system('sudo fwkill')

@pytest.fixture
def fixture_globals():
    start_time = datetime.now()

    yield

    end_time = datetime.now()
    print("Elapsed: " + str(end_time - start_time))
