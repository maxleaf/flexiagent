import subprocess
import time
#import test_command

if __name__ == '__main__':
    state = {'proc':None, 'output':'', 'error':'', 'returncode':0}
    #cmd = "python3.6 ./fw_test_command.py"
    cmd = "python3.6 /usr/share/flexiwan/agent/tools/fwdump.py"
    try:
        state['proc'] = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, universal_newlines=True, executable="/bin/sh")
        (state['output'], state['error']) = state['proc'].communicate(timeout=100)
    except OSError as err:
        state['error'] = str(err)
        print("Error executing command '%s', error: %s" % (str(cmd), str(err)))
    except Exception as err:
        state['error'] = "Error executing command '%s', error: %s" % (str(cmd), str(err))
        print("Error executing command '%s', error: %s" % (str(cmd), str(err)))
    state['returncode'] = state['proc'].returncode    

    print (("%s %d ") % (state['output'], state['returncode']))