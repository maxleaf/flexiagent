import os
import time
import subprocess
import shlex
import threading

gateway_stats = {}
WINDOW_SIZE = 30
LOSS_THRESHOLD = 50.0

def check_output(cmd, stderr=subprocess.STDOUT):
    """Run bash command

    :param cmd:         Bash command
    :param stderr:      Where to print errors

    :returns: Command execution result
    """
    if "|" in cmd:
        cmd_parts = cmd.split('|')
    else:
        cmd_parts = [cmd]
    for i, part in enumerate(cmd_parts):
        args = shlex.split(part)
        if i == 0:
            out = subprocess.Popen(args, stdin=None, stdout=subprocess.PIPE, stderr=stderr)
        else:
            out = subprocess.Popen(args, stdin=out.stdout, stdout=subprocess.PIPE, stderr=stderr)
    return out.communicate()[0]

def update_gateway_metric(ip, line, new_metric):
    """Update gateway metric, if isAvailable, set to low metric
    Otherwise set to high metric (lower priority)

    :param ip: gateway IP
    :param line: full ip route line
    :isAvailable: True when loss above threshold, False loss below threshold

    :returns: None
    """
    if 'metric ' in line:
        part1 = line.split('metric ')
        part2 = part1[1].split(' ')
        part2[0] = str(new_metric)
        part1[1] = ' '.join(part2)
        new_line = 'metric '.join(part1)
    else:
        new_line = line + ' metric ' + str(new_metric)

    if (line != new_line):
        cmd = "sudo ip route del " + line
        new_cmd = "sudo ip route add " + new_line
        check_output(cmd)
        check_output(new_cmd)

def get_gateways():
    """Get all gateways and metrics from the system

    :param None

    :returns: List of dictionaries for every gateway containing:
    - line: the full line as shown in ip route command
    - ip: the gateway ip
    - metric: the gateway metric, '' if not exist
    - proto: the route protocol, '' if not exist
    """
    cmd = 'ip route list match default | grep via'
    gateways = check_output(cmd).splitlines()
    res = {}
    for gw in gateways:
        metric = '100'
        proto = ''
        gwIp = gw.split('via ')[1].split(' ')[0]
        if 'metric ' in gw:
            metric = gw.split('metric ')[1].split(' ')[0]
        if 'proto ' in gw:
            proto = gw.split('proto ')[1].split(' ')[0]
        if proto == 'static' or proto == 'dhcp':
            res[gwIp] = {'line':gw, 'proto':proto, 'metric':metric}
    return res

def ping_and_update_gateways_stats():
    """Ping all gateways and update the stats

    :param None

    :returns: None
    """

    # get current gateways
    gateways = get_gateways()

    # keep only existing gateways
    currentGws = set(gateways)
    statsGws = set(gateway_stats)
    gwToRemove = statsGws.difference(currentGws)
    for gw in gwToRemove:
        del gateway_stats[gw]

    # Loop through all gateways and try to ping them, update their stats
    for gw in gateways.keys():
        # create an entry if not exist
        if gw not in gateway_stats:
            gateway_stats[gw] = {
                'rtts':[]
            }

        rtts = gateway_stats[gw]['rtts']

        cmd = "fping %s -C 1 -q" % (gw)
        output = check_output(cmd).splitlines()
        rtt = output[0].split(': ')[-1]
        rtts.append(rtt)
        if len(rtts) > WINDOW_SIZE:
            rtts = rtts[-WINDOW_SIZE:]

        print (rtts, rtts.count('-'), len(rtts))
        loss = 0.0 if len(rtts)<WINDOW_SIZE else (1.0*rtts.count('-')/len(rtts)) * 100.0
        print ("GW=%s, Loss=%f %%") % (gw, loss)

        metric = int(gateways[gw]['metric'])
        if loss > LOSS_THRESHOLD and metric <10000:
            update_gateway_metric(gw, gateways[gw]['line'], metric+10000)
        if loss <= LOSS_THRESHOLD and metric >=10000:
            update_gateway_metric(gw, gateways[gw]['line'], metric-10000)

def run():
    while True:
        # Update gateway stats every second
        ping_and_update_gateways_stats()
        time.sleep(1)

run()

