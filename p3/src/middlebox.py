#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from threading import *
from random import randint, random
import time


def load_droprate(path):
    with open(path, 'r') as f:
        text = f.read()
    args = text.split()
    assert len(args) == 2
    assert args[0] == '-d'
    drop_rate = float(args[1])
    assert 0.0 <= drop_rate and drop_rate <= 1.0
    return drop_rate

def should_i_drop(drop_rate):
    return random() < drop_rate

def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    mac_mapping = {'blaster': '10:00:00:00:00:01',
            'blastee': '20:00:00:00:00:01'}

    drop_rate = load_droprate('middlebox_params.txt')

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
            log_debug("I got a packet {}".format(pkt))

        if dev == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            if not should_i_drop(drop_rate):
                pkt[Ethernet].src = my_intf.interface_by_name("middlebox-eth1").ethaddr
                ptk[Ethernet].dst = mac_mapping['blastee']
                net.send_packet("middlebox-eth1", pkt)
        elif dev == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            '''
            pkt[Ethernet].src = my_intf.interface_by_name("middlebox-eth0").ethaddr
            ptk[Ethernet].dst = mac_mapping['blaster']
            net.send_packet("middlebox-eth0", pkt)
        else:
            log_debug("Oops :))")

    net.shutdown()
