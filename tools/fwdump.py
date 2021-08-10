#! /usr/bin/python3
import os
import re
import subprocess
import sys
import time

agent_root_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..')
sys.path.append(agent_root_dir)

class FwDump:

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return None

    def dump(self):
#        cmd = 'export COLUMNS=200; '
        cmd = 'ps -elf | grep watchdog > linux_pid.log; '
        '''
        cmd += 'which ps >> linux_pid.log; '
        cmd += 'which grep >> linux_pid.log; '
        cmd += 'alias >> linux_pid.log; '
        cmd += 'env >> linux_pid.log; '
        '''
        try:
            print("Command: %s" % cmd)
            subprocess.check_call(cmd, shell=True)
        except Exception as e:
            print('warning: dumper %s failed' % (str(e)))

def main():
    with FwDump() as dump:
        dump.dump()
        print('done:')


if __name__ == '__main__':

    cmd = 'env > linux_before.log; '
    try:
        print("Command: %s" % cmd)
        subprocess.check_call(cmd, shell=True)
    except Exception as e:
        print('warning: dumper %s failed' % (str(e)))

    import fwutils

    cmd = 'env > linux_after.log; '
    try:
        print("Command: %s" % cmd)
        subprocess.check_call(cmd, shell=True)
    except Exception as e:
        print('warning: dumper %s failed' % (str(e)))    
    main()
