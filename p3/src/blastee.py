#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from threading import *
import time
from copy import deepcopy

def read_arguments(path):
    with open(path, 'r') as f:
        text = f.read()
    args = text.split()
    assert len(args) == 4
    opts = {}
    for i in range(0, 4, 2):
        if args[i] == '-b':
            opts['blaster_ip'] = args[i+1]
        elif args[i] == '-n':
            opts['num_pkts'] = int(args[i+1])
            assert opts['num_pkts'] >= 0
    return opts

def unpack_data_bytes(data):
    seq_num = int.from_bytes(data[0:4], byteorder='big')
    length = int.from_bytes(data[4:6], byteorder='big')
    payload = data[6:].decode('utf-8', 'ignore')
    return seq_num, length, payload

def pack_ack_bytes(seq_num, payload):
    seq_bytes = seq_num.to_bytes(4, byteorder='big')
    payload_padded = payload + '\0' * 8
    payload_bytes = payload_padded[:8].encode('utf-8', 'ignore')
    return seq_bytes + payload_bytes

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    mac_mapping = {'middlebox-eth1': '40:00:00:00:00:02'}

    opts = read_arguments('blastee_params.txt')
    while True:
        gotpkt = True
        try:
            dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))

            bytes_data = pkt[RawPacketContents].to_bytes()
            seq_num, length, payload = unpack_data_bytes(bytes_data)

            ack_pkt = deepcopy(pkt)
            # modify ethaddr
            ack_pkt[Ethernet].src = my_intf.interface_by_name("blastee-eth0").ethaddr
            ack_pkt[Ethernet].dst = mac_mapping['middlebox-eth1']
            # modify ipaddr
            iphdr = ack_pkt[IPv4]
            iphdr.src, iphdr.dst = iphdr.dst, iphdr.src
            # modify udp
            udphdr = ack_pkt[UDP]
            udphdr.src, udphdr.dst = udphdr.dst, udphdr.src
            ack_pkt[RawPacketContents] = RawPacketContents(
                    pack_ack_bytes(seq_num, payload))
            net.send_packet("blastee-eth0", ack_pkt)

    net.shutdown()
