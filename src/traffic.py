from socket import socket, inet_aton, htons, AF_PACKET, SOCK_RAW
import numpy as np
import struct

ids = []
seq = 8760
PROTO_MPLS = 0x8847
PROTO_IPV4 = 0x0800


def generate(number_of_bytes):
    return np.random.bytes(number_of_bytes)


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
    
    return struct.pack(f'!{len(labels)}I', *mpls)

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
        src = int.from_bytes(inet_aton(src), 'big')

    if dst is None:
        dst = int.from_bytes(generate(4), byteorder='big')
    else:
        dst = int.from_bytes(inet_aton(dst), 'big')

    if payload is None:
        payload = udp()

    checksum = 0
    global seq
    hdr = struct.pack('!BBHHHBBHII', 0x45, 0x00, len(payload) + 20,
                seq, 0x4000,
                ttl, 0x11, checksum, 
                src, dst)
    hdr = struct.pack('!BBHHHBBHII', 0x45, 0x00, len(payload) + 20,
                seq, 0x4000,
                ttl, 0x11, chksum(hdr), 
                src, dst)
    seq += 1
    return hdr + payload    


def udp(data=None, src=None, dst=None):
    '''gen 1456 bytes '''
    if src is None:
        src = int.from_bytes(generate(2), byteorder='big')
    if dst is None:
        dst = int.from_bytes(generate(2), byteorder='big')
    else:
        dst = dst #htons(dst)

    if data is None:
        data = generate(100)
    
    checksum = 0
    hdr = struct.pack('!4H', src, dst, len(data) + 8, checksum)
    hdr = struct.pack('!4H', src, dst, len(data) + 8, chksum(hdr))
    
    return hdr + data


def chksum(payload):
    checksum = sum([int.from_bytes(payload[p:p+2], 'big') for p in range(0, len(payload), 2)])
    
    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16) 
    
    return ~checksum & 0xffff


if __name__ == '__main__':
    ifname = 'ens160'
    # next hop 10.124.209.195 00:50:56:97:09:75
    mac_src, mac_dst = '00:50:56:97:9a:7f', '00:50:56:97:8c:bc'
    ip_src, ip_dst = '10.1.1.1', '192.2.235.235'
    #paths = [17]
    paths = [18215,17113,17014,17007,17111]
    #17001/17003/16194
    num_to_send = 1

    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((ifname, 0))

    import time
    num = 0
    while num < num_to_send:
        #packet = eth_hdr(mac_dst, mac_src, PROTO_IPV4) + \
        packet = eth_hdr(mac_dst, mac_src, PROTO_MPLS) + \
            mpls_hdr(paths) + \
            ip_payload(ip_src, ip_dst, payload=udp(dst=4521))
        r = s.send(packet)
        print(f'{num+1} sent {r} bytes!')
        num += 1
        time.sleep(1)

    print(f'Total sent {num_to_send}.')
