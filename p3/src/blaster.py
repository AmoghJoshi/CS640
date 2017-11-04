#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from random import randint
import time


def read_arguments(path):
    with open(path, 'r') as f:
        text = f.read()
    args = text.split()
    assert len(args) == 12
    opts = {}
    for i in range(0, 12, 2):
        if args[i] == '-b':
            opts['blastee_ip'] = args[i+1]
        elif args[i] == '-n':
            opts['num_pkts'] = int(args[i+1])
            assert opts['num_pkts'] >= 0
        elif args[i] == '-l':
            opts['length'] = int(args[i+1])
            assert opts['length'] >= 0 and opts['length'] <= 65535
        elif args[i] == '-w':
            opts['window'] = int(args[i+1])
            assert opts['window'] > 0
        elif args[i] == '-t':
            opts['timeout'] = float(args[i+1])
            assert opts['timeout'] > 0
        elif args[i] == '-r':
            opts['recv_timeout'] = float(args[i+1])
            assert opts['recv_timeout'] > 0
    return opts

def unpack_ack_bytes(data):
    seq_num = int.from_bytes(data[0:4], byteorder='big')
    payload = data[4:].decode('utf-8', 'ignore')
    return seq_num, payload

def pack_data_bytes(seq_num, payload):
    seq_bytes = seq_num.to_bytes(4, byteorder='big')
    payload_bytes = payload.encode('utf-8', 'ignore')
    length_bytes = len(payload_bytes).to_bytes(2, byteorder='big')
    return seq_bytes + length_bytes + payload_bytes

def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    opts = read_arguments('blaster_params.txt')

    mac_mapping = {'middlebox-eth0': '40:00:00:00:00:01'}

    next_seq_num = 0
    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            dev,pkt = net.recv_packet(timeout=0.15)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            # TODO: process the ack
            log_debug("I got a packet")
        else:
            log_debug("Didn't receive anything")

            '''
            Creating the headers for the packet
            '''
            eth_hdr = Ethernet(src=mymacs[0], dst=mac_mapping['middlebox-eth0'],
                    ethertype=EtherType.IP)
            ip_hdr = IPv4(src=myips[0], dst='192.168.200.1', protocol=IPProtocol.UDP, ttl=64)
            udp_hdr = UDP(src=8080, dst=80)
            contents_hdr = RawPacketContents(pack_data_bytes(next_seq_num, 'hello cs640'))
            pkt = eth_hdr + ip_hdr + udp_hdr + contents_hdr
            '''
            Do other things here and send packet
            '''
            next_seq_num += 1
            net.send_packet("blaster-eth0", pkt)

    net.shutdown()
