from socket import socket, inet_ntoa, inet_aton, htons, AF_PACKET, SOCK_RAW, IPPROTO_UDP
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
import sys
import logging

ETH_MPLS_UNICAST = 0x8847
ETH_IPV4 = 0x0800
ETH_ALL = 3
killed = False

MODE_RECEIVER = 'receiver'
MODE_SENDER = 'sender'
MODE_SYNC = 'sync'
MODE_THREAD = 'thread'


class Stats:
    def __init__(self, total):
        self.total = total
        self.min = 65535000
        self.max = 0
        self.received = 0
        self.sum = 0
        self.last = 0

    def update(self, latency):
        self.last = time.time()
        self.received += 1
        self.sum += latency

        if latency > self.max:
            self.max = latency
        if latency < self.min:
            self.min = latency

    def finished(self):
        return self.received == self.total

    def is_timeout(self, timeout):
        return time.time() - self.last > timeout

    def __str__(self):
        return f'Total sent {self.received}/{self.total}, ' \
               f'success {int(self.received / self.total * 100)}%, ' \
               f'min {int(self.min * 1000)} ms, max {int(self.max * 1000)} ms, ' \
               f'avg {int(self.sum / self.received * 1000)} ms'


def generate(number_of_bytes):
    """
    generate random bytes
    :param number_of_bytes: total number to generate
    :return: bytes generated
    """
    return bytes(bytearray(getrandbits(8) for _ in range(number_of_bytes)))


def encode_srdata(index, total=0, interval=1, identifier=0):
    """
    generate data with identifier, timestamp, index, total and interval, with extra 100 bytes
    :param index: sequence number of the packet to send
    :param total: total number to send
    :param interval: packet sending interval
    :param identifier: instance id of sender
    :return: packed bytes
    """
    data = struct.pack('!2d3H', time.time(), interval, index, total, identifier)
    data += generate(100)
    return data


def decode_srdata(data):
    """
    decode received bytes into sr data
    :param data:
    :return: timestamp, interval, sequence, total and identifier
    """
    timestamp, interval, index, total, identifier = struct.unpack('!2d3H', data[:22])
    return timestamp, interval, index, total, identifier


def eth_hdr(dst, src, proto=ETH_IPV4):
    """
    generate eth header
    :param dst: destination mac address
    :param src: source mac address
    :param proto: l2 protocol, IPv4 as default
    :return: packed bytes
    """
    hdr = struct.pack('!6B', *[int(x, 16) for x in dst.split(':')])
    hdr += struct.pack('!6B', *[int(x, 16) for x in src.split(':')])
    hdr += struct.pack('!H', proto)

    return hdr


def mpls_hdr(labels, ttl=63):
    """
    generate mpls header
    :param labels: mpls labels to add
    :param ttl: ttl of each label, 63 as default
    :return: generated bytes
    """
    mpls = []
    for i, label in enumerate(labels):
        bottom = 0 if i + 1 < len(labels) else 1
        o = (label << 4) | bottom
        o = (o << 8) | ttl
        mpls.append(o)

    return struct.pack(f'!{len(labels)}I', *mpls)


def ip_payload(seq, src=None, dst=None, payload=None, ttl=63):
    """
    generate ip header and payload.
    version: 4, hdr_len: 20
    dscp: 0, ecn: 0
    total_len: payload_len + hdr_len
    id: 2bytes
    :param seq: fragment sequence
    :param src: source ip address
    :param dst: destination ip address
    :param payload: payload bytes
    :param ttl: ttl of the ip packet
    :return: bytes generated
    """

    checksum = 0
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0x00, len(payload) + 20,
        seq, 0x4000, ttl, IPPROTO_UDP, checksum, inet_aton(src), inet_aton(dst))
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0x00, len(payload) + 20,
        seq, 0x4000, ttl, IPPROTO_UDP, chksum(hdr), inet_aton(src), inet_aton(dst))
    return hdr + payload


def decode_ip_hdr(data):
    """
    decode ip header
    :param data: bytes received
    :return: dict of seq, ttl, src, dst ip address and protocol code
    """
    packet = struct.unpack('!BBHHHBBH4s4s', data[:20])
    seq, ttl, proto = packet[3], packet[5], packet[6]
    src, dst = inet_ntoa(packet[8]), inet_ntoa(packet[9])
    return {'seq': seq, 'ttl': ttl, 'src': src, 'dst': dst, 'proto': proto}


def udp(data=None, sport=None, dport=None):
    """
    generate udp packet, generate random port if source or destination port was not set,
    generate random 100 bytes if payload wasn't set
    :param data: payload to send
    :param sport: source port
    :param dport: destination port
    :return: byte generated
    """
    if sport is None:
        sport = int.from_bytes(generate(2), byteorder='big')
    if dport is None:
        dport = int.from_bytes(generate(2), byteorder='big')

    if data is None:
        data = generate(100)

    checksum = 0
    hdr = struct.pack('!4H', sport, dport, len(data) + 8, checksum)
    hdr = struct.pack('!4H', sport, dport, len(data) + 8, chksum(hdr))

    return hdr + data


def chksum(payload):
    """
    calculate checksum of ip packet
    :param payload: ip packet to send
    :return: calculated checksum
    """
    # sum up each 2 bytes
    checksum = sum([int.from_bytes(payload[p:p+2], 'big') for p in range(0, len(payload), 2)])
    # round it into 2 bytes
    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    # in case of overflow
    return ~checksum & 0xffff


def recv(sock, timeout, stats, sync=False, identifier=0):
    """
    receive packets and stats
    print stats while all packets of an instance were received or timeout.
    :param sock: socket to receive from
    :param timeout: timeout in second
    :param stats: result stats
    :param sync: running mode
    :param identifier: 0 means running in MODE_RECEIVER
    :return: None
    """
    time_left = timeout
    recv_stats = {}

    while (sync and time_left > 0) or not killed:
        tick = time.time()
        ready = select.select([sock], [], [], time_left)
        received = time.time()
        time_left = timeout if not sync else time_left - (received - tick)

        if len(ready) == 0:
            continue

        packet = sock.recv(2048)
        if len(packet) < 34:
            logging.info('Unknown packet received.')
        else:
            # TODO check udp port
            ipv4_hdr = decode_ip_hdr(packet[14:34])
            if ipv4_hdr['proto'] != IPPROTO_UDP:  # not the packet we've sent
                logging.info(f'Unknown packet({ipv4_hdr["proto"]}) received.')
                continue

            if len(packet) < 64:
                logging.info(f'Unknown packet,{len(packet)}, {ipv4_hdr["src"]}, {ipv4_hdr["dst"]}, {ipv4_hdr["seq"]}')
            else:
                timestamp, interval, index, total, recv_id = decode_srdata(packet[42:64])
                latency = received - timestamp
                seq, ttl, src, dst = ipv4_hdr['seq'], ipv4_hdr['ttl'], ipv4_hdr['src'], ipv4_hdr['dst']
                # check identifier
                if identifier != 0 and identifier != recv_id:
                    logging.info('Irrelevant packet received.')
                    continue

                if identifier == recv_id:
                    print(f'{src} <-> {dst}: ttl {ttl}, latency {latency * 1e3} ms')
                    stats.update(latency)
                    if sync:
                        return

                if identifier == 0:
                    # receive all the packets of the identifier or the last packet timeout
                    res = recv_stats.get(recv_id, Stats(total))
                    res.update(latency)
                    recv_stats[recv_id] = res

                    if res.finished():
                        print(f'Instance {recv_id} test finished!', res)
                        recv_stats.pop(recv_id, None)
                    # check timeout
                    for k, s in recv_stats.items():
                        if s.is_timeout(timeout):
                            print(f'Instance {k} timeout, {s}')
                            del recv_stats[k]

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
    parser.add_argument('-m', '--mode', default='thread',
                        help='Running mode, sender, receiver, thread, sync, default thread')
    parser.add_argument('-t', '--interval', type=float, default=1.0, help='Sending interval in millisecond')
    parser.add_argument('labels', metavar='Label', nargs='*', type=int, help='mpls labels to pass by')

    args = parser.parse_args()
    if args.mode not in [MODE_RECEIVER, MODE_SENDER, MODE_SYNC, MODE_THREAD]:
        print('Mode only support {}, {}, {}, {}, please check', MODE_THREAD, MODE_SYNC, MODE_SENDER, MODE_RECEIVER)
        sys.exit(1)

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

    mode = args.get('mode')
    ifname = args.get('interface')
    s = socket(AF_PACKET, SOCK_RAW, ETH_ALL)
    s.bind((ifname, ETH_ALL))

    # next hop 10.124.209.195 00:50:56:97:09:75
    mac_src, mac_dst = args.get('mac_src'), args.get('mac_dst')
    ip_src, ip_dst, port = args.get('ip_src'), args.get('ip_dst'), args.get('port')
    paths = args.get('labels')
    keep, interval = args.get('keep'), args.get('interval')
    num_to_send = 0 if keep else args.get('count')
    timeout, num, seq = 3, 0, randint(1000, 65536)
    identifier = 0 if mode == MODE_RECEIVER else seq
    stats = Stats(num_to_send)

    if mode in [MODE_RECEIVER, MODE_THREAD]:
        recv_thread = threading.Thread(target=recv, args=(s, timeout, stats, False, identifier))
        recv_thread.start()

        if mode == MODE_RECEIVER:
            print('Receiver is running...')
            return

    print(f'{ip_src} <-> {ip_dst} via: {paths}')

    global killed
    while keep or num < num_to_send:
        if killed:
            break

        packet = eth_hdr(mac_dst, mac_src, ETH_MPLS_UNICAST if len(paths) > 0 else IPPROTO_UDP)
        if len(paths) > 0:
            packet += mpls_hdr(paths)
        data = encode_srdata(num, num_to_send, interval, identifier)
        packet += ip_payload(seq, ip_src, ip_dst, payload=udp(data=data, dport=port))
        s.send(packet)
        if mode == MODE_SYNC:
            recv(s, timeout, stats, True, identifier)

        num += 1
        seq += 1
        time.sleep(interval)

    killed = True
    if mode == MODE_SENDER:
        print(f'Total sent {num}')
    else:
        print(stats)


if __name__ == '__main__':
    run()
    main_thread = threading.main_thread()
    for t in threading.enumerate():
        if t is not main_thread:
            t.join()
