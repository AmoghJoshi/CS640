#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net
        self.my_interfaces = net.interfaces()
        # other initialization stuff here
        self.ethaddrs = set([intf.ethaddr for intf in self.my_interfaces])
        self.ipaddrs = set([intf.ipaddr for intf in self.my_interfaces])
        self.ip2eth = dict()

    def process_arp(pkt, input_port):
        arp = pkt.get_header(Arp)
        # store the mapping, applicable for both REQUEST and REPLY
        self.ip2eth[arp.senderprotoaddr] = arp.senderhwaddr
        # REQUEST
        if arp.operation == ArpOperation.Request:
            if arp.targetprotoaddr in self.ipaddrs:
                # send the ARP response
                arp_reply = create_ip_arp_reply(arp.senderhwaddr,
                        self.net.interface_by_ipaddr(arp.targetprotoaddr).ethaddr,
                        arp.senderprotoaddr, arp.targetprotoaddr)
                self.net.send_packet(input_port, arp_reply)

    def broadcast_arp_request(target_ip_addr):
        for intf in self.my_interfaces:
            arp_req = create_ip_arp_request(intf.ethaddr, intf.ipaddr, target_ip_addr)
            self.net.send_packet(intf.ethaddr, arp_req)

    def process_packet(pkt, input_port):
        pkt_type = type(pkt)
        if pkt_type is Arp:
            process_arp(pkt, input_port)

    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))



def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
