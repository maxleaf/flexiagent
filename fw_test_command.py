#! /usr/bin/python3
import subprocess

if __name__ == '__main__':
    try:
        print('Dump ps output')
        subprocess.check_call('ps -elf | grep vpp >> tmp.txt', shell=True)
    except Exception as e:
        print('warning: dumper failed, error %s' % (str(e))) 
    