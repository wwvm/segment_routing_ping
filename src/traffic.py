from socket import socket, AF_PACKET, SOCK_RAW, inet_aton
import numpy as np
import struct
import pprint


def generate(number_of_bytes):
    return np.random.bytes(number_of_bytes)

# save sent packet id
ids = []
seq = 1000
payload_len = 1000
PROTO_MPLS = 0x8847
PROTO_IPV4 = 0x0800


def eth_hdr(dst, src, proto=PROTO_IPV4):
    ''' return raw packet '''
    #hdr = struct.pack('', src, dst, proto)
    #data = [0x52, 0x54, 0x00, 0x12, 0x35, 0x02, 0xfe, 0xed, 0xfa, 
    #                         0xce, 0xbe, 0xef, 0x08, 0x00]
    #hdr = struct.pack('!14B', *data)
    hdr = struct.pack('!6B', *[int(x, 16) for x in dst.split(':')])
    hdr += struct.pack('!6B', *[int(x, 16) for x in src.split(':')])
    hdr += struct.pack('!H', proto)

    return hdr


def mpls_hdr(labels, ttl=63):
    ''' return mpls header '''
    mpls = []
    for i, label in enumerate(labels):
        bottom = 0 if i + 1 < len(labels) else 1
        o = (label << 4) | (0 << 3) | bottom
        o = (o << 8) | ttl
        mpls.append(o)
    
    return struct.pack(f'!{len(mpls)}I', *mpls)


def ip_payload(src=None, dst=None, payload=None, ttl=63):
    ''' return ip header
    version: 4, hdr_len: 20
    dscp: 0, ecn: 0
    total_len: payload_len + hdr_len
    id: 2bytes
    '''
    if src is None:
        src = int.from_bytes(generate(4), byteorder='big')
    else:
        src = inet_aton(src)

    if dst is None:
        dst = int.from_bytes(generate(4), byteorder='big')
    else:
        dst = inet_aton(dst)

    if payload is None:
        payload = udp()

    global seq
    checksum = 0
    hdr = struct.pack('!BBHHHBBHII', 0x45, 0x00, len(payload) + 20,
                seq, 0x4000,
                ttl, 0x11, checksum, 
                src, dst)
    checksum = chksum(hdr)
    hdr = struct.pack('!BBHHHBBHII', 0x45, 0x00, len(payload) + 20,
                seq, 0x4000,
                ttl, 0x11, checksum, 
                src, dst)
    seq += 1
    return hdr + payload    


def udp(data=40000, src=40000, dst=None):
    '''gen random bytes, src and dst is the port'''
    #if src is None:
    #    src = int.from_bytes(generate(2), byteorder='big')
    #if dst is None:
    #    dst = int.from_bytes(generate(2), byteorder='big')

    if data is None:
        data = generate(payload_len)
    
    checksum = 0
    # skip checksum
    hdr = struct.pack('!4H', src, dst, len(data) + 8, checksum)
    checksum = chksum(hdr)
    hdr = struct.pack('!4H', src, dst, len(data) + 8, checksum)
    
    return hdr + data


def chksum(payload):
    checksum = sum([int.from_bytes(payload[p:p+2], 'big') for p in range(0, len(payload), 2)])
    
    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16) 
    
    return ~checksum & 0xffff


if __name__ == '__main__':
    addr = ('ens192', 0)
    num_to_send = 1
    mac_src, mac_dst = '00:50:56:88:c9:54', '00:50:56:88:c9:51'
    path_mpls_labels = [17003, 17011, 17113, 24004]

    s = socket(AF_PACKET, SOCK_RAW)
    s.bind(addr)
    sent = 0
    while sent < num_to_send:
        r = s.send(eth_hdr(mac_dst, mac_src, PROTO_MPLS) + mpls_hdr(path_mpls_labels) + ip_payload())
        print('sent bytes: ', r)
        sent += 1
