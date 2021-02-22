import pytest
import os 
import glob
import shutil
import yaml
import json
import subprocess
import re
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


def pytest_addoption(parser):
    parser.addoption(
        "--interface-1", action="store", default="pci:0000:00:08.00", help="Interface to use"
    )
    parser.addoption(
        "--interface-2", action="store", default="pci:0000:00:09.00", help="Interface to use"
    )
    parser.addoption(
        "--interface-3", action="store", default="pci:0000:00:03.00", help="Interface to use"
    )

@pytest.fixture
def currpath(request):
    return str(request.node.fspath)

@pytest.fixture
def interface_1(request):
    return request.config.getoption('--interface-1')

@pytest.fixture
def interface_2(request):
    return request.config.getoption('--interface-2')

@pytest.fixture
def interface_3(request):
    return request.config.getoption('--interface-3')

@pytest.fixture(autouse=True)
def prepare_cli_files(currpath):
    vendor = subprocess.check_output("lshw -c system | awk '/vendor/{print tolower($2)}' 2>&1", shell=True).strip()

    data = None
    with open(os.path.abspath('./fwtests.yaml'), 'r') as stream:
        info = yaml.load(stream, Loader=yaml.BaseLoader)
        for env in info['devices']:
            if vendor == env:
                data = info['devices'][env]

    tests_path = currpath.replace('.py', '')
    # get original tests files
    test_cases = sorted(glob.glob('%s/*.cli' % tests_path))
    expected_files = sorted(glob.glob('%s/*configuration_dump.json' % tests_path))
    original_files = test_cases + expected_files

    def _replace(item):
        # use template
        if isinstance(item, str) or isinstance(item, unicode):
            return data[item]

        # use specific field
        elif type(item) == dict:
            for key, value in item.items():
                match = re.search('(__INTERFACE_[1-3]__)(.*)', value)
                if match:
                    interface, field = match.groups()
                    item[key] = data[interface][field]
        return item

    for file in original_files:
        # copy original file and save
        if 'json' in file:
            copy_path = file.replace('.json', '.orig_json')
        else:
            copy_path = file.replace('.cli', '.orig_cli')
        shutil.copyfile(file, copy_path)

        # replace tests variables
        with open(file, 'r+') as json_file:
            requests = json.load(json_file)
            for req in requests:
                if not 'params' in req:
                    continue

                msg = req['message']
                if msg == 'start-router':
                    interfaces = req['params']['interfaces'] if 'interfaces' in req['params'] else None
                    if interfaces:
                        for idx, interface in enumerate(interfaces):
                            updated_interface = _replace(interface)
                            interfaces[idx] = updated_interface

                with open(file, 'w+') as json_file:
                    json.dump(requests, json_file, sort_keys=True, indent=1)
            # print(cfg)
        
        a = 'a'

        # os.system("sed -i 's/%s/%s/g' %s" % ("__INTERFACE_1__", interface_1, file))
        # os.system("sed -i 's/%s/%s/g' %s" % ("__INTERFACE_2__", interface_2, file))
        # os.system("sed -i 's/%s/%s/g' %s" % ("__INTERFACE_3__", interface_3, file))

    # yield

    # # get modified files
    # modified_test_cases = sorted(glob.glob('%s/*.cli' % tests_path))
    # modified_expected_files = sorted(glob.glob('%s/*.json' % tests_path))
    # modified_files = modified_test_cases + modified_expected_files

    # # remove all modified files
    # for file in modified_files:
    #     os.remove(file)

    # # get original tests files and restored them
    # original_files = sorted(glob.glob('%s/*orig_*' % tests_path))
    # for file in original_files:
    #     # copy original file and save
    #     if 'orig_json' in file:
    #         copy_path = file.replace('.orig_json', '.json')
    #     else:
    #         copy_path = file.replace('.orig_cli', '.cli')
    #     shutil.move(file, copy_path)