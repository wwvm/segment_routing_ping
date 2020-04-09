from socket import socket, inet_ntoa, inet_aton, htons, AF_PACKET, SOCK_RAW
import numpy as np
import ipaddress
import struct
import select
import binascii
import argparse
import netifaces as nic
from getmac import get_mac_address
import time

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


def recv(sock, id, tick, timeout):
    time_left = timeout
    while time_left > 0:
        started = time.time()
        ready = select.select([sock], [], [], time_left)
        elapsed = time.time() - started
        if len(ready) == 0:
            return
        received = time.time()
        pkt = sock.recv(2048)
        data = struct.unpack('!BBHHHBBHII', pkt[14:34])
        time_left -= received - tick
        rseq, ttl, src, dst = data[3], data[5], data[8], data[9]
        if rseq + 1 == seq:
            print(f'{ipaddress.IPv4Address(src)} <-> {ipaddress.IPv4Address(dst)}: ttl {ttl}, latency {(received - tick) * 1e6} us')
            return
    print('Timeout')


def parseArgs():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-i', '--interface', required=True, help='source interface to use')
    parser.add_argument('-n', '--nexthop', dest='nexthop', required=True, help='next hop IP address')
    parser.add_argument('-d', '--destination', help='destination IP address')
    parser.add_argument('-c', '--count', nargs='?', type=int, default=10, help='Num of packet to sent')
    parser.add_argument('-t', '--keep', action='store_true', help='Keep sending the packets')
    parser.add_argument('labels', metavar='Label', nargs='*', type=int, help='mpls labels to pass by')

    args = parser.parse_args()
    # get MAC and ip from inteface
    addrs = nic.ifaddresses(args.interface)
    mac_src = addrs[nic.AF_LINK][0]['addr']
    ip_src = addrs[nic.AF_INET][0]['addr']

    # get MAC from next hop
    mac_dst = get_mac_address(ip=args.nexthop)

    # destination
    ip_dst = ip_src if args.destination is None else args.destination

    return {'interface': args.interface, 'mac_src': mac_src, 'mac_dst': mac_dst, 'ip_src': ip_src, 'ip_dst': ip_dst,
            'count': args.count, 'keep': args.keep, 'labels': args.labels}


if __name__ == '__main__':
    args = parseArgs()

    ifname = args.get('interface')
    # next hop 10.124.209.195 00:50:56:97:09:75
    mac_src, mac_dst = args.get('mac_src'), args.get('mac_dst')
    ip_src, ip_dst = args.get('ip_src'), args.get('ip_dst')
    paths = args.get('labels')
    num_to_send = args.get('count')

    s = socket(AF_PACKET, SOCK_RAW, htons(3))
    s.bind((ifname, 3))
    s.setblocking(0)

    num = 0
    print(f'sending packet with path: {paths}')
    while args.get('keep') or num < num_to_send:
        packet = eth_hdr(mac_dst, mac_src, PROTO_MPLS if len(paths) > 0 else PROTO_IPV4)
        if len(paths) > 0:
            packet += mpls_hdr(paths)
        packet += ip_payload(ip_src, ip_dst, payload=udp(dst=4521))
        r = s.send(packet)
        num += 1
        recv(s, None, time.time(), 3)
        time.sleep(1)

    print(f'Total sent {num_to_send}.')
