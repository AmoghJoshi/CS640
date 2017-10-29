#!/usr/bin/env python3

'''
interfaces
router-eth0 mac:10:00:00:00:00:01 ip:192.168.1.1/24
router-eth1 mac:10:00:00:00:00:02 ip:10.10.0.1/16
router-eth2 mac:10:00:00:00:00:03 ip:172.16.42.1/30
raw forward table:
    172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
    172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
    172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
    10.100.0.0 255.255.0.0 172.16.42.2 router-eth2
'''

from switchyard.lib.userlib import *
import time

class HostInterface(object):
    def __init__(self, eth_addr, ip_addr):
        self.eth_addr = eth_addr
        self.ip_addr = ip_addr


def arp_tests():
    s = TestScenario("ARP request and reply")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1', '255.255.255.0')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '10.10.0.1', '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '172.16.42.1', '255.255.255.252')
    s.add_file('forwarding_table.txt', '''172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
        172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
        172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
        10.100.0.0 255.255.0.0 172.16.42.2 router-eth2''')

    intfs = [s.interfaces()['router-eth{}'.format(i)] for i in range(3)]

    # Hosts in network  192.168.1.0/24 -> router-eth0
    hosts0 = [HostInterface('20:00:00:00:00:{:02d}'.format(i), '192.168.1.{}'.format(i))
            for i in range(2,5)]
    # Hosts in network  10.0.0.1/16 -> router-eth1
    hosts1 = [HostInterface('30:00:00:00:00:{:02d}'.format(i), '10.0.0.{}'.format(i))
            for i in range(2,5)]
    # Hosts in network  172.16.42.1/30 -> router-eth2
    hosts2 = [HostInterface('40:00:00:00:00:{:02d}'.format(i), '172.16.42.{}'.format(i))
            for i in range(2,3)]
    # Hosts in network  172.16.0.0/16 -> router-eth0
    hosts3 = [HostInterface('50:00:00:00:00:{:02d}'.format(i), '172.16.192.{}'.format(i))
            for i in range(2,6)]
    # Hosts in network  172.16.128.0/18 -> router-eth1
    hosts4 = [HostInterface('60:00:00:00:00:{:02d}'.format(i), '172.16.128.{}'.format(i))
            for i in range(2,5)]
    # Hosts in network  172.16.64.0/18 -> router-eth1
    hosts4 = [HostInterface('60:00:00:00:00:{:02d}'.format(i), '172.16.128.{}'.format(i))
            for i in range(2,5)]
    # Hosts in network  10.100.0.0/16 -> router-eth2
    hosts6 = [HostInterface('80:00:00:00:00:{:02d}'.format(i), '10.100.0.{}'.format(i))
            for i in range(2,5)]

    broadcast_eth = 'ff:ff:ff:ff:ff:ff'
    broadcast_ip ='255.255.255.255'

    '''
    test case 1: receive ARP requests
    '''
    # from net0
    pkt1 = create_ip_arp_request(hosts0[0].eth_addr, hosts0[0].ip_addr, intfs[0].ipaddr)
    s.expect(PacketInputEvent(intfs[0].name, pkt1, display=Arp), "ARP request for {} should arrive on {}".format(intfs[0].ipaddr, intfs[0].name))
    pkt2 = create_ip_arp_reply(intfs[0].ethaddr, hosts0[0].eth_addr, intfs[0].ipaddr, hosts0[0].ip_addr)
    s.expect(PacketOutputEvent(intfs[0].name, pkt2, display=Arp), "Router should send ARP reply for {} on {}".format(intfs[0].ipaddr, intfs[0].name))

    # from net1
    pkt3 = create_ip_arp_request(hosts1[0].eth_addr, hosts1[0].ip_addr, intfs[1].ipaddr)
    s.expect(PacketInputEvent(intfs[1].name, pkt3, display=Arp), "ARP request for {} should arrive on {}".format(intfs[1].ipaddr, intfs[1].name))
    pkt4 = create_ip_arp_reply(intfs[1].ethaddr, hosts1[0].eth_addr, intfs[1].ipaddr, hosts1[0].ip_addr)
    s.expect(PacketOutputEvent(intfs[1].name, pkt4, display=Arp), "Router should send ARP reply for {} on {}".format(intfs[1].ipaddr, intfs[1].name))

    # from net2
    pkt5 = create_ip_arp_request(hosts2[0].eth_addr, hosts2[0].ip_addr, intfs[2].ipaddr)
    s.expect(PacketInputEvent(intfs[2].name, pkt5, display=Arp), "ARP request for {} should arrive on {}".format(intfs[2].ipaddr, intfs[2].name))
    pkt6 = create_ip_arp_reply(intfs[2].ethaddr, hosts2[0].eth_addr, intfs[2].ipaddr, hosts2[0].ip_addr)
    s.expect(PacketOutputEvent(intfs[2].name, pkt6, display=Arp), "Router should send ARP reply for {} on {}".format(intfs[2].ipaddr, intfs[2].name))

    # invalid arp. The router should drop it
    pkt7 = create_ip_arp_request(hosts2[0].eth_addr, hosts2[0].ip_addr, hosts1[2].ip_addr)
    s.expect(PacketInputEvent(intfs[2].name, pkt7, display=Arp), "ARP request for {} should arrive on {}".format(intfs[2].ipaddr, intfs[2].name))

    return s


scenario = arp_tests()
