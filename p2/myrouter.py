#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
import threading
from switchyard.lib.userlib import *


class ForwardTable(object):
    def __init__(self, path):
        def parse_entry(entry):
            items = entry.split()
            return IPv4Network(items[0] + '/' + items[1]), \
                    IPv4Address(items[2]), items[3]
        with open(path, 'r') as f:
            text = f.read()
        print('raw forward table:')
        print(text)
        self.table = list(map(parse_entry, filter(None, text.split('\n')) ))
        print(self.table)

    def lookup(self, ipv4_addr):
        matching_entry = None
        for netwk, nexthop, eth_port in self.table:
            if ipv4_addr in netwk:
                if matching_entry is None or matching_entry[2] < netwk.prefixlen:
                    matching_entry = (nexthop, eth_port, netwk.prefixlen)
        return matching_entry


class PendingPackets(object):
    def __init__(self, pkt, timestamp, count, out_intf):
        self.pkts = [pkt]
        self.timestamp = timestamp
        self.count = count
        self.out_intf = out_intf

    def add(self, pkt):
        self.pkts.append(pkt)


class Router(object):
    TIMEOUT_INTERVAL = 1

    def __init__(self, net):
        self.net = net
        self.my_interfaces = net.interfaces()
        print('interfaces')
        for intf in self.my_interfaces:
            print(intf)
        # other initialization stuff here
        self.ethaddrs = set([intf.ethaddr for intf in self.my_interfaces])
        self.ipaddrs = set([intf.ipaddr for intf in self.my_interfaces])
        self.arp_mapping = dict()
        self.pending_pkts = dict()      # <dst, list[PendingPackets]>
        if os.path.exists('forwarding_table.txt'):
            self.fwd_table = ForwardTable('forwarding_table.txt')

    def process_arp(self, pkt, input_port):
        arp = pkt.get_header(Arp)
        # store the mapping, applicable for both REQUEST and REPLY
        self.arp_mapping[arp.senderprotoaddr] = arp.senderhwaddr
        if arp.operation == ArpOperation.Request:   # REQUEST
            if arp.targetprotoaddr in self.ipaddrs:
                # send the ARP response
                arp_reply = create_ip_arp_reply(
                        self.net.interface_by_ipaddr(arp.targetprotoaddr).ethaddr,
                        arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                self.net.send_packet(input_port, arp_reply)
        # process pending packets
        if arp.senderprotoaddr in self.pending_pkts:
            cur_pending_pkts = self.pending_pkts[arp.senderprotoaddr]
            intf = self.net.interface_by_name(input_port)
            for cur_pending_pkt in cur_pending_pkts.pkts:
                self.forwarding_ip_packet(cur_pending_pkt, intf, arp.senderprotoaddr)
            del self.pending_pkts[arp.senderprotoaddr]

    def forwarding_ip_packet(self, pkt, intf, nexthop_ipaddr):
        pkt[Ethernet].src = intf.ethaddr
        pkt[Ethernet].dst = self.arp_mapping[nexthop_ipaddr]
        self.net.send_packet(intf.name, pkt)

    def process_ipv4(self, pkt, input_port):
        ip_hdr = pkt.get_header(IPv4)
        ip_hdr.ttl = ip_hdr.ttl - 1   # what if ttl == 0?
        if ip_hdr.dst in self.ipaddrs:
            return # drop the packet intended for the router
        # import pdb; pdb.set_trace()
        # first check the interfaces
        intf = None
        for intf0 in self.my_interfaces:
            if int(ip_hdr.dst) & int(intf0.netmask) == int(intf0.ipaddr) & int(intf0.netmask):
                next_hop = ip_hdr.dst
                intf = intf0
                break
        # then lookup in the forwarding table
        if intf is None:
            match_entry = self.fwd_table.lookup(ip_hdr.dst)
            if match_entry is None:
                log_info('pkt {} mismatched. Dropped'.format(ip_hdr))
                return # drop if mismatch
            next_hop, eth_port, _ = match_entry
            intf = self.net.interface_by_name(eth_port)
        if next_hop not in self.arp_mapping:
            if next_hop in self.pending_pkts:
                self.pending_pkts[next_hop].add(pkt)
            else:
                self.pending_pkts[next_hop] = PendingPackets(pkt, time.time() - 2, 0, intf)
        else:
            self.forwarding_ip_packet(pkt, intf, next_hop)

    def process_packet(self, pkt, input_port):
        if pkt.has_header(Arp):
            log_debug("{} has an ARP header".format(pkt))
            self.process_arp(pkt, input_port)
        elif pkt.has_header(IPv4):
            log_debug("{} has an IPv4 header".format(pkt))
            self.process_ipv4(pkt, input_port)

    def broadcast_arp_request(self, intf, target_ip_addr):
        arp_req = create_ip_arp_request(intf.ethaddr, intf.ipaddr, target_ip_addr)
        self.net.send_packet(intf.name, arp_req)

    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            time_now = time.time()
            remove_list = []
            for tar_ip_addr, pending_pkt in self.pending_pkts.items():
                # import pdb; pdb.set_trace()
                if pending_pkt.timestamp + 1 < time_now:  # time to broadcast again
                    if pending_pkt.count < 5:
                        pending_pkt.count += 1
                        pending_pkt.timestamp = time_now
                        log_info('broadcast ARP req to {} {}th attempt'.format(tar_ip_addr, pending_pkt.count))
                        self.broadcast_arp_request(pending_pkt.out_intf, tar_ip_addr)
                    else:
                        remove_list.append(tar_ip_addr)
                        log_info('arp to {} failed five times. drop all packets'.format(tar_ip_addr))
            for ipaddr in remove_list:
                del self.pending_pkts[ipaddr]

            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=Router.TIMEOUT_INTERVAL)
            except NoPackets:
                log_info("No packets available in recv_packet")
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
