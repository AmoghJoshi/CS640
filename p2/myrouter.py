#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *

class ForwardTable(object):
    def __init__(self, path):
        def parse_entry(entry):
            items = entry.split()
            return IPv4Network(items[0] + '/' + items[1]), \
                    IPv4Address(items[2]), items[3]
        with open(path, 'r') as f:
            text = f.read()
            self.table = list(map(parse_entry, text.split('\n')))
            print(self.table)

    def lookup(self, ipv4_addr):
        matching_entry = None
        for netwk, nexthop, eth_port in self.table:
            if ipv4_addr in netwk:
                if matching_entry is None or matching_entry[2] < netwk.prefixlen:
                    matching_entry = (nexthop, eth_port, netwk.prefixlen)
        return matching_entry


class Router(object):
    def __init__(self, net):
        self.net = net
        self.my_interfaces = net.interfaces()
        # other initialization stuff here
        self.ethaddrs = set([intf.ethaddr for intf in self.my_interfaces])
        self.ipaddrs = set([intf.ipaddr for intf in self.my_interfaces])
        self.ip2eth = dict()
        if os.path.exists('forwarding_table.txt'):
            self.fwd_table = ForwardTable('forwarding_table.txt')

    def process_arp(self, pkt, input_port):
        arp = pkt.get_header(Arp)
        # store the mapping, applicable for both REQUEST and REPLY
        self.ip2eth[arp.senderprotoaddr] = arp.senderhwaddr
        # REQUEST
        if arp.operation == ArpOperation.Request:
            if arp.targetprotoaddr in self.ipaddrs:
                # send the ARP response
                arp_reply = create_ip_arp_reply(
                        self.net.interface_by_ipaddr(arp.targetprotoaddr).ethaddr,
                        arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                self.net.send_packet(input_port, arp_reply)

    def broadcast_arp_request(self, eth_port, target_ip_addr):
        arp_req = create_ip_arp_request(intf.ethaddr, intf.ipaddr, target_ip_addr)
        self.net.send_packet(eth_port, arp_req)
        count = 0
        while count < 5 and not gotpkt:
            try:
                # TODO: get out of blocked
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet. {}th attempt.".format(count+1))
                gotpkt = False
            else:
                gotpkt = True
            except Shutdown:
                log_debug("Got shutdown signal")
                return
            finally:
                count += 1
        self.process_arp(pkt, dev)

    def process_ipv4(self, pkt, input_port):
        pkt.ttl = pkt.ttl - 1
        ip_hdr = pkt.get_header(IPv4)
        if ip_hdr.dst in self.ipaddrs:
            return # drop the packet intended for the router
        match_entry = self.fwd_table.lookup(ip_hdr.dst)
        if match_entry is None:
            return # drop if mismatch
        # forwarding
        next_hop, eth_port, _ = match_entry
        if next_hop not in self.ip2eth:
            self.broadcast_arp_request(eth_port, next_hop)
        pkt[Ethernet].src = self.net.interface_by_name(eth_port).ethaddr
        pkt[Ethernet].dst = self.ip2eth[next_hop]
        self.net.send_packet(eth_port, pkt)

    def process_packet(self, pkt, input_port):
        if pkt.has_header(Arp):
            log_debug("{} has an ARP header".format(pkt))
            self.process_arp(pkt, input_port)
        elif pkt.has_header(IPv4):
            log_debug("{} has an IPv4 header".format(pkt))
            self.process_ipv4(pkt, input_port)


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

            self.process_packet(pkt, dev)



def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
