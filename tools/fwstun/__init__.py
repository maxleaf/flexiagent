import binascii
import random
import socket
import os
import errno
import sys
import traceback
globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)

__version__ = '1.0.0'

g_stun_log = None # log object

STUN_SERVERS = (
    'stun.l.google.com:19302',
    'stun1.l.google.com:19302',
    'stun2.l.google.com:19302',
    'stun3.l.google.com:19302',
    'stun4.l.google.com:19302',
    'stun.ekiga.net:3478',
    'stun.cheapvoip.com:3478',
    'stun.gmx.de:3478',
    'stun.gmx.net:3478',
    'stun.stunprotocol.org:3478',
)

"""
for testing none responsive STUN server

STUN_SERVERS = (
 'stun.voxgratia.org',
)
"""

stun_servers_list = STUN_SERVERS
MagicCookie = '2112a442'

DEFAULTS = {
    'stun_port': 3478,
    'source_ip': '0.0.0.0',
    'source_port': 54320
}

# stun attributes
MappedAddress = '0001'
ResponseAddress = '0002'
ChangeRequest = '0003'
SourceAddress = '0004'
ChangedAddress = '0005'
Username = '0006'
Password = '0007'
MessageIntegrity = '0008'
ErrorCode = '0009'
UnknownAttribute = '000A'
ReflectedFrom = '000B'
XorOnly = '0021'
XorMappedAddress = '0020'
ServerName = '8022'
SecondaryAddress = '8050'  # Non standard extension

# types for a stun message
BindRequestMsg = '0001'
BindResponseMsg = '0101'
BindErrorResponseMsg = '0111'
SharedSecretRequestMsg = '0002'
SharedSecretResponseMsg = '0102'
SharedSecretErrorResponseMsg = '0112'

# type for a vxLAN message
vxLanMsg = '08000000'

dictAttrToVal = {'MappedAddress': MappedAddress,
                 'ResponseAddress': ResponseAddress,
                 'ChangeRequest': ChangeRequest,
                 'SourceAddress': SourceAddress,
                 'ChangedAddress': ChangedAddress,
                 'Username': Username,
                 'Password': Password,
                 'MessageIntegrity': MessageIntegrity,
                 'ErrorCode': ErrorCode,
                 'UnknownAttribute': UnknownAttribute,
                 'ReflectedFrom': ReflectedFrom,
                 'XorOnly': XorOnly,
                 'XorMappedAddress': XorMappedAddress,
                 'ServerName': ServerName,
                 'SecondaryAddress': SecondaryAddress}

dictMsgTypeToVal = {
    'BindRequestMsg': BindRequestMsg,
    'BindResponseMsg': BindResponseMsg,
    'BindErrorResponseMsg': BindErrorResponseMsg,
    'SharedSecretRequestMsg': SharedSecretRequestMsg,
    'SharedSecretResponseMsg': SharedSecretResponseMsg,
    'SharedSecretErrorResponseMsg': SharedSecretErrorResponseMsg}

dictValToMsgType = {}

dictValToAttr = {}

Blocked = "Blocked"
OpenInternet = "Open Internet"
FullCone = "Full Cone"
SymmetricUDPFirewall = "Symmetric UDP Firewall"
RestricNAT = "Restric NAT"
RestricPortNAT = "Restric Port NAT"
SymmetricNAT = "Symmetric NAT"
ChangedAddressError = "Error"

def b2a_hexstr(abytes):
    return binascii.b2a_hex(abytes).decode("ascii")

def xor_convert(abytes, xor_str):
    bytes_len = len(abytes)
    if (bytes_len != len(xor_str)/2 or len(xor_str)%2 !=0):
        stun_log("Stun: missmatch xor_convert. %s, %s" % (str(abytes), xor_str))
        return abytes
    xor_bytes = binascii.a2b_hex(xor_str)
    res = bytearray(bytes_len)
    for i in range(bytes_len):
        res[i] = abytes[i] ^ xor_bytes[i]
    return res

def _initialize():
    global dictValToAttr, dictValToMsgType
    dictValToAttr= {v: k for k, v in list(dictAttrToVal.items())}
    dictValToMsgType = {v: k for k, v in list(dictMsgTypeToVal.items())}

def set_log(log):
    global g_stun_log
    g_stun_log = log

def gen_tran_id():
    a = ''.join(random.choice('0123456789ABCDEF') for i in range(24))
    # return binascii.a2b_hex(a)
    return a

def stun_test(sock, host, port, source_ip, source_port, send_data=""):
    retVal = {'Resp': False, 'ExternalIP': None, 'ExternalPort': None,
              'SourceIP': None, 'SourcePort': None, 'ChangedIP': None,
              'ChangedPort': None}
    str_len = "%#04d" % (len(send_data) / 2)
    trans_id = MagicCookie + gen_tran_id()
    str_data = ''.join([BindRequestMsg, str_len, trans_id, send_data])
    data = binascii.a2b_hex(str_data)

    for _ in range (2):
        stun_log("Stun: sendto: %s:%s" %(str(host), str(port)))
        try:
            sock.sendto(data, (host, port))
        except Exception as e:
            retVal['Resp'] = False
            return retVal
        try:
            buf, addr = sock.recvfrom(2048)
            stun_log("Stun: recvfrom: %s" %(str(addr)))
        except Exception as e:
            stun_log("Stun: recvfrom: %s" %(str(e)), 'warning')
            continue

        msgtype = b2a_hexstr(buf[0:2])
        try:
            # from some reason we sometimes get msgtype u'00800' resulting KeyError exception
            bind_resp_msg = dictValToMsgType[msgtype] == "BindResponseMsg"
        except KeyError:
            stun_log("Stun: received unknown message type: %s" %(msgtype))
            retVal['Resp'] = False
            return retVal
        trans_id_match = trans_id.upper() == b2a_hexstr(buf[4:20]).upper()
        if not bind_resp_msg or not trans_id_match:
            continue

        len_message = int(b2a_hexstr(buf[2:4]), 16)
        len_remain = len_message
        base = 20
        while len_remain:
            attr_type = b2a_hexstr(buf[base:(base + 2)])
            attr_len = int(b2a_hexstr(buf[(base + 2):(base + 4)]), 16)
            # add protection for buffer boundaries
            if attr_len > len_remain and attr_len <= 12:
                retVal['Resp'] = True
                return retVal
            if attr_type == MappedAddress:
                port = int(b2a_hexstr(buf[base + 6:base + 8]), 16)
                ip = ".".join([
                    str(int(b2a_hexstr(buf[base + 8:base + 9]), 16)),
                    str(int(b2a_hexstr(buf[base + 9:base + 10]), 16)),
                    str(int(b2a_hexstr(buf[base + 10:base + 11]), 16)),
                    str(int(b2a_hexstr(buf[base + 11:base + 12]), 16))
                ])
                retVal['ExternalIP'] = ip
                retVal['ExternalPort'] = port
            if attr_type == XorMappedAddress:
                port = int(b2a_hexstr(xor_convert(buf[base + 6:base + 8], MagicCookie[0:4])), 16)
                ip = ".".join([
                    str(int(b2a_hexstr(xor_convert(buf[base + 8:base + 9], MagicCookie[0:2])), 16)),
                    str(int(b2a_hexstr(xor_convert(buf[base + 9:base + 10], MagicCookie[2:4])), 16)),
                    str(int(b2a_hexstr(xor_convert(buf[base + 10:base + 11], MagicCookie[4:6])), 16)),
                    str(int(b2a_hexstr(xor_convert(buf[base + 11:base + 12], MagicCookie[6:8])), 16))
                ])
                retVal['ExternalIP'] = ip
                retVal['ExternalPort'] = port
            if attr_type == SourceAddress:
                port = int(b2a_hexstr(buf[base + 6:base + 8]), 16)
                ip = ".".join([
                    str(int(b2a_hexstr(buf[base + 8:base + 9]), 16)),
                    str(int(b2a_hexstr(buf[base + 9:base + 10]), 16)),
                    str(int(b2a_hexstr(buf[base + 10:base + 11]), 16)),
                    str(int(b2a_hexstr(buf[base + 11:base + 12]), 16))
                ])
                retVal['SourceIP'] = ip
                retVal['SourcePort'] = port
            if attr_type == ChangedAddress:
                port = int(b2a_hexstr(buf[base + 6:base + 8]), 16)
                ip = ".".join([
                    str(int(b2a_hexstr(buf[base + 8:base + 9]), 16)),
                    str(int(b2a_hexstr(buf[base + 9:base + 10]), 16)),
                    str(int(b2a_hexstr(buf[base + 10:base + 11]), 16)),
                    str(int(b2a_hexstr(buf[base + 11:base + 12]), 16))
                ])
                retVal['ChangedIP'] = ip
                retVal['ChangedPort'] = port

            base = base + 4 + attr_len
            len_remain = len_remain - (4 + attr_len)
        retVal['Resp'] = True
        return retVal

    return retVal

def get_nat_type(s, source_ip, source_port, stun_host, stun_port, idx_start):
    _initialize()
    port = stun_port
    stun_log("Stun: Do Test1")
    resp = False
    found_idx = 0
    if stun_host:
        ret = stun_test(s, stun_host, port, source_ip, source_port)
        resp = ret['Resp']
    else:
        list_len = len(stun_servers_list)
        for idx in range(idx_start, idx_start+list_len):
            stun_host_ = stun_servers_list[idx%list_len]
            #FLEXIWAN_FIX: handle STUN server addresses in the form of ip:port
            stun_info = stun_host_.split(':')
            stun_host_ = stun_info[0]
            if len (stun_info) == 2:
                port = int(stun_info[1])
            else:
                port = 3789
            stun_log('Stun: Trying STUN host: %s' %(stun_host_))
            ret = stun_test(s, stun_host_, port, source_ip, source_port)
            resp = ret['Resp']
            if resp:
                found_idx = idx
                stun_host = stun_host_
                break

    if not resp:
        return Blocked, ret, ''
    stun_log("Stun: Result: %s" %(ret))
    exIP = ret['ExternalIP']
    exPort = ret['ExternalPort']
    changedIP = ret['ChangedIP']
    changedPort = ret['ChangedPort']
    if ret['ExternalIP'] == source_ip:
        changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
        ret = stun_test(s, stun_host, port, source_ip, source_port,
                        changeRequest)
        if ret['Resp']:
            typ = OpenInternet
        else:
            typ = SymmetricUDPFirewall
    else:
        changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
        stun_log("Stun: Do Test2")
        ret = stun_test(s, stun_host, port, source_ip, source_port,
                        changeRequest)
        stun_log("Stun: Result: %s" %(ret))
        if ret['Resp']:
            typ = FullCone
        else:
            stun_log("Stun: Do Test1")
            ret = stun_test(s, changedIP, changedPort, source_ip, source_port)
            stun_log("Stun: Result: %s" %(ret))
            if not ret['Resp']:
                typ = SymmetricNAT
            else:
                if exIP == ret['ExternalIP'] and exPort == ret['ExternalPort']:
                    changePortRequest = ''.join([ChangeRequest, '0004',
                                                 "00000002"])
                    stun_log("Stun: Do Test3")
                    ret = stun_test(s, changedIP, port, source_ip, source_port,
                                    changePortRequest)
                    stun_log("Stun: Result: %s" %(ret))
                    if ret['Resp']:
                        typ = RestricNAT
                    else:
                        typ = RestricPortNAT
                else:
                    typ = SymmetricNAT
    # restore previously learned exIP and exPort in case of `RestricPortNat`
    if ret['ExternalIP'] is None and exIP is not None:
        ret['ExternalIP'] = exIP
    if ret['ExternalPort'] is None and exPort is not None:
        ret['ExternalPort'] = exPort
    return typ, ret, found_idx


def get_ip_info(source_ip="0.0.0.0", source_port=4789, stun_host=None,
                stun_port=3478, dev_name = None, idx = 0):
    """
    This function is the outside API to the stun client module.
    It retrieves the STUN type, the public IP as seen from the STUN on the other side of the
    NAT, and the public port.
    : param source_ip   : the local source IP on behalf NAT request is sent
    : param source_port : the local source port on behalf NAT request is sent
    : param stun_host   : the stun server host name or IP address
    : param stun_port   : the stun server port
    : param dev_name    : device name to bind() to
    : param idx         : index in list of STUN servers, pointing to the server to send STUN from

    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        stun_log("get_ip_info, binding to %s:%d" %(source_ip, source_port))
        if dev_name != None:
            s.setsockopt(socket.SOL_SOCKET, 25, dev_name.encode())
        s.bind((source_ip, source_port))
    except Exception as e:
        stun_log("get_ip_info: bind: %s" % str(e))
        s.close()
        return ('', '', '', '')

    nat_type, nat, stun_idx = get_nat_type(s, source_ip, source_port, \
                                stun_host=stun_host, stun_port=stun_port, idx_start = idx)
    external_ip = nat['ExternalIP'] if nat['ExternalIP'] != None else ''
    external_port = nat['ExternalPort'] if nat['ExternalPort'] != None else ''
    s.close()
    nat_type = '' if nat_type == None else nat_type
    return (nat_type, external_ip, external_port, stun_idx)

def stun_log(string, level = 'debug'):
    """ Log string to log file
    : param string : string to print into the log
    : param level  : severity as a string (e.g. 'debug')
    """
    if not g_stun_log:
        return
    func = getattr(g_stun_log, level)
    if func:
        func(string)

def get_remote_ip_info(source_ip="0.0.0.0", source_port=4789, dev_name = None):
    """
    This function is the outside API to the symmetric nat traversal.
    It retrieves the remote IP and PORT as seen from incoming packets from the other side of the tunnel.
    : param source_ip   : the local source IP on behalf NAT request is sent
    : param source_port : the local source port on behalf NAT request is sent
    : param dev_name    : device name to bind() to

    """
    tunnels = {}
    pkts_to_read = 10
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        stun_log("Tunnel: binding to %s:%d" %(source_ip, source_port))
        if dev_name != None:
            sock.setsockopt(socket.SOL_SOCKET, 25, dev_name.encode())
        sock.bind((source_ip, source_port))
    except Exception as e:
        stun_log("Tunnel: bind: %s" % str(e))
        sock.close()
        return tunnels

    for _ in range(pkts_to_read):
        try:
            buf, (address, port) = sock.recvfrom(2048)
            stun_log("Tunnel: recvfrom: %s:%s" %(str(address), str(port)))
        except socket.timeout as e:
            stun_log("Tunnel: There are no packets: %s" %(str(e)), 'warning')
            break
        except Exception as e:
            stun_log("Tunnel: recvfrom: %s" %(str(e)), 'warning')
            continue

        if len(buf) < 8:
            continue

        msgtype = b2a_hexstr(buf[0:4])
        if msgtype == vxLanMsg:
            vni = int(b2a_hexstr(buf[4:7]), 16)
            if not tunnels.get(vni):
                tunnels[vni] = {"dst" : address, "dstPort" : port}
            stun_log("Tunnel: msgtype: %s vni: %s" %(str(msgtype), str(vni)))

    sock.close()
    return tunnels
