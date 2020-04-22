from socket import socket, inet_ntoa, inet_aton, htons, AF_PACKET, SOCK_RAW
# import numpy as np
# import ipaddress
import struct
import select
import binascii
import argparse
import netifaces as nic
from getmac import get_mac_address
import time
import signal
from random import randint, getrandbits
import threading

ETH_MPLS_UNICAST = 0x8847
ETH_IPV4 = 0x0800
IP_UDP = 0x11
ETH_ALL = 3
killed = False


def generate(number_of_bytes):
    # return np.random.bytes(number_of_bytes)
    return bytes(bytearray(getrandbits(8) for _ in range(number_of_bytes)))


def encode_srdata(index, total=0, interval=1):
    """
    generate data with identifier, timestamp, index, total and interval
    """
    identifier, timestamp = 0, time.time()
    data = struct.pack('!2d3H', timestamp, interval, index, total, identifier)
    data += generate(100)
    return data


def decode_srdata(data):
    timestamp, interval, index, total, identifier = struct.unpack('!2d3H', data[:22])
    return timestamp, interval, index, total, identifier


def eth_hdr(dst, src, proto=ETH_IPV4):
    """ return raw packet """
    hdr = struct.pack('!6B', *[int(x, 16) for x in dst.split(':')])
    hdr += struct.pack('!6B', *[int(x, 16) for x in src.split(':')])
    hdr += struct.pack('!H', proto)

    return hdr


def mpls_hdr(labels, ttl=63):
    """ return mpls header """
    mpls = []
    for i, label in enumerate(labels):
        bottom = 0 if i + 1 < len(labels) else 1
        o = (label << 4) | (0 << 3) | bottom
        o = (o << 8) | ttl
        mpls.append(o)

    return struct.pack(f'!{len(labels)}I', *mpls)


def ip_payload(seq, src=None, dst=None, payload=None, ttl=63):
    """ return ip header
    version: 4, hdr_len: 20
    dscp: 0, ecn: 0
    total_len: payload_len + hdr_len
    id: 2bytes
    """
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
    hdr = struct.pack('!BBHHHBBHII', 0x45, 0x00, len(payload) + 20,
        seq, 0x4000, ttl, IP_UDP, checksum, src, dst)
    hdr = struct.pack('!BBHHHBBHII', 0x45, 0x00, len(payload) + 20,
        seq, 0x4000, ttl, IP_UDP, chksum(hdr), src, dst)
    return hdr + payload


def decode_ip_hdr(data):
    packet = struct.unpack('!BBHHHBBH4s4s', data[:20])
    seq, ttl, proto = packet[3], packet[5], packet[6]
    src, dst = inet_ntoa(packet[8]), inet_ntoa(packet[9])
    return {'seq': seq, 'ttl': ttl, 'src': src, 'dst': dst, 'proto': proto}


def udp(data=None, src=None, dst=None):
    """gen 1456 bytes """
    if src is None:
        src = int.from_bytes(generate(2), byteorder='big')
    if dst is None:
        dst = int.from_bytes(generate(2), byteorder='big')
    else:
        dst = dst  # htons(dst)

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


def recv(sock, timeout, result, sync=False):
    """
    receive packets and stats
    print stats while all packets of an instance were received.
    :param sock:
    :param timeout:
    :param result:
    :param sync:
    :return:
    """
    time_left = timeout
    while (sync and time_left > 0) or not killed:
        tick = time.time()
        ready = select.select([sock], [], [], time_left)
        received = time.time()
        time_left = timeout if not sync else time_left - (received - tick)

        if len(ready) == 0:
            continue

        packet = sock.recv(2048)
        if len(packet) < 34:
            print('not a valid ip v4 packet')
        else:
            ipv4_hdr = decode_ip_hdr(packet[14:34])
            if ipv4_hdr['proto'] != IP_UDP:  # not the packet we've sent
                continue

            if len(packet) < 64:
                print('not a valid sr test packet', ipv4_hdr['src'], ipv4_hdr['dst'], ipv4_hdr['seq'])
                print(len(packet), binascii.hexlify(packet))
            else:
                timestamp, interval, index, total, identifier = decode_srdata(packet[42:64])
                latency = received - timestamp
                seq, ttl, src, dst = ipv4_hdr['seq'], ipv4_hdr['ttl'], ipv4_hdr['src'], ipv4_hdr['dst']
                print(f'{src} <-> {dst}: ttl {ttl}, latency {latency * 1e3} ms')

                if latency > result['max']:
                    result['max'] = latency
                if latency < result['min']:
                    result['min'] = latency

                result['sum'] += latency
                result['received'] += 1
        if sync:
            return
        else:
            continue
    if not killed:
        print('Timeout')


def parse_args():
    parser = argparse.ArgumentParser(description='Ping function for testing segment routing over MPLS')
    parser.add_argument('-i', '--interface', required=True, help='Which interface to use')
    parser.add_argument('-n', '--nexthop', required=True, help='The IP of next hop')
    parser.add_argument('-s', '--source', help='Source IP')
    parser.add_argument('-d', '--destination', help='Destination IP')
    parser.add_argument('-p', '--port', type=int, default=4521, help='UDP port to use')
    parser.add_argument('-c', '--count', type=int, default=10, help='Num of packet to sent')
    parser.add_argument('-k', '--keep', action='store_true', help='Keep sending the packets')
    parser.add_argument('-m', '--mode', default='thread', help='Running mode, sender, receiver, thread, sync, default thread')
    parser.add_argument('-t', '--interval', type=float, default=1.0, help='Sending interval in millisecond')
    parser.add_argument('labels', metavar='Label', nargs='*', type=int, help='mpls labels to pass by')

    args = parser.parse_args()
    # get MAC and ip from interface
    addrs = nic.ifaddresses(args.interface)
    mac_src = addrs[nic.AF_LINK][0]['addr']
    ip_src = addrs[nic.AF_INET][0]['addr'] if args.source is None else args.source

    # get MAC from next hop
    mac_dst = get_mac_address(ip=args.nexthop)

    # destination
    ip_dst = addrs[nic.AF_INET][0]['addr'] if args.destination is None else args.destination

    return {
        'interface': args.interface,
        'mac_src': mac_src,
        'mac_dst': mac_dst,
        'ip_src': ip_src,
        'ip_dst': ip_dst,
        'count': args.count,
        'keep': args.keep,
        'labels': args.labels,
        'port': args.port,
        'interval': args.interval,
        'mode': args.mode
    }


def sig_handler(signo, frame):
    global killed
    killed = True


def run():
    args = parse_args()

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    # TODO receiver mode
    ifname = args.get('interface')
    s = socket(AF_PACKET, SOCK_RAW, ETH_ALL)
    s.bind((ifname, ETH_ALL))
    result = {'sum': 0, 'max': 0, 'min': 65536000, 'received': 0}
    timeout = 3

    if args.get('mode') == 'thread' or args.get('mode') == 'receiver':
        recv_thread = threading.Thread(target=recv, args=(s, timeout, result,))
        recv_thread.start()

        if args.get('mode') == 'receiver':
            print('Receiver is running...')
            return

    # next hop 10.124.209.195 00:50:56:97:09:75
    mac_src, mac_dst = args.get('mac_src'), args.get('mac_dst')
    ip_src, ip_dst = args.get('ip_src'), args.get('ip_dst')
    paths = args.get('labels')
    num_to_send = args.get('count') if not args.get('keep') else 0

    print(f'{ip_src} <-> {ip_dst} via: {paths}')
    num, seq = 0, randint(1000, 65536)

    global killed
    while args.get('keep') or num < num_to_send:
        if killed:
            break

        packet = eth_hdr(mac_dst, mac_src, ETH_MPLS_UNICAST if len(paths) > 0 else ETH_IPV4)
        if len(paths) > 0:
            packet += mpls_hdr(paths)
        data = encode_srdata(seq, num_to_send, args.get('interval'))
        packet += ip_payload(seq, ip_src, ip_dst, payload=udp(data=data, dst=args.get('port')))
        s.send(packet)
        if args.get('mode') == 'sync':
            recv(s, timeout, result, True)

        num += 1
        seq += 1
        time.sleep(args.get('interval'))

    killed = True
    if args.get('mode') == 'sender':
        print(f'Total sent {num}')
        return

    print('Total sent {}/{}, success {}%, min {} ms, max {} ms, avg {} ms'.format(
        result['received'], num, int(result['received'] / num * 100),
        int(result["min"] * 1000), int(result["max"] * 1000), int(result["sum"]/result["received"] * 1000)))


if __name__ == '__main__':
    run()
    main_thread = threading.main_thread()
    for t in threading.enumerate():
        if t is not main_thread:
            t.join()
