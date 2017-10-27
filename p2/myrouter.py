#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
import threading
from switchyard.lib.userlib import *

next_tid = 0

class ArpMapping(object):
    def __init__(self):
        self.ip2eth_lock = threading.Lock()
        self.ip2eth = dict()

    def put(self, arp):
        self.ip2eth_lock.acquire()
        self.ip2eth[arp.senderprotoaddr] = arp.senderhwaddr
        self.ip2eth_lock.release()

    def contains(self, ipv4_addr):
        return ipv4_addr in self.ip2eth

    def get(self, ipv4_addr):
        return self.ip2eth[ipv4_addr]


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


class BackgroundForwarding(threading.Thread):
    def __init__(self, tid, net, arp_mapping, intf, next_hop, pending_pkt):
        threading.Thread.__init__(self)
        self.net = net
        self._tid = tid
        self._arp_mapping = arp_mapping
        self._intf = intf
        self._next_hop = next_hop
        self._pending_pkt = pending_pkt

    def run(self):
        log_debug('start thread {}'.format(self._tid))
        if self._arp_mapping.contains(self._next_hop):
            self.broadcast_arp_request(self._intf, self._next_hop)
        pkt[Ethernet].src = self._intf.ethaddr
        pkt[Ethernet].dst = self._arp_mapping.get(self._next_hop)
        self.net.send_packet(self._intf.name, self._pending_pkt)

    def broadcast_arp_request(self, intf, target_ip_addr):
        arp_req = create_ip_arp_request(intf.ethaddr, intf.ipaddr, target_ip_addr)
        self.net.send_packet(intf.name, arp_req)
        count = 0
        gotpkt = False
        while count < 5 and not gotpkt:
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
                if pkt.has_header(Arp):
                    arp_hdr = pkt.get_header(Arp)
                    if arp_hdr.operation = Arp.Reply and arp_hdr.senderprotoaddr == target_ip_addr:
                        gotpkt = True
            except NoPackets:
                log_debug("No packets available in recv_packet. {}th attempt.".format(count+1))
            except Shutdown:
                log_debug("Got shutdown signal")
                return
            finally:
                count += 1
        self.process_arp(pkt, dev)


class Router(object):
    def __init__(self, net):
        self.net = net
        self.my_interfaces = net.interfaces()
        # other initialization stuff here
        self.ethaddrs = set([intf.ethaddr for intf in self.my_interfaces])
        self.ipaddrs = set([intf.ipaddr for intf in self.my_interfaces])
        self.arp_mapping = ArpMapping()
        self.bg_threads = []
        if os.path.exists('forwarding_table.txt'):
            self.fwd_table = ForwardTable('forwarding_table.txt')

    def process_arp(self, pkt, input_port):
        arp = pkt.get_header(Arp)
        # store the mapping, applicable for both REQUEST and REPLY
        self.arp_mapping.put(arp)
        # REQUEST
        if arp.operation == ArpOperation.Request:
            if arp.targetprotoaddr in self.ipaddrs:
                # send the ARP response
                arp_reply = create_ip_arp_reply(
                        self.net.interface_by_ipaddr(arp.targetprotoaddr).ethaddr,
                        arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                self.net.send_packet(input_port, arp_reply)

    def process_ipv4(self, pkt, input_port):
        pkt.ttl = pkt.ttl - 1
        ip_hdr = pkt.get_header(IPv4)
        if ip_hdr.dst in self.ipaddrs:
            return # drop the packet intended for the router
        self.match_entry = self.fwd_table.lookup(ip_hdr.dst)
        if self.match_entry is None:
            return # drop if mismatch
        # forwarding
        next_hop, eth_port, _ = match_entry
        intf = self.net.interface_by_name(eth_port)
        self.bg_threads.append(BackgroundForwarding(next_tid, self.net, self.arp_mapping, intf, next_hop, pkt))
        next_tid += 1
        self.bg_threads[-1].start()



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
