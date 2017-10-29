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

def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=32):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=ttl)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt

def ip_forwarding_tests():
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
    hosts1 = [HostInterface('30:00:00:00:00:{:02d}'.format(i), '10.10.0.{}'.format(i))
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
    hosts5 = [HostInterface('60:00:00:00:00:{:02d}'.format(i), '172.16.64.{}'.format(i))
            for i in range(2,5)]
    # Hosts in network  10.100.0.0/16 -> router-eth2
    hosts6 = [HostInterface('80:00:00:00:00:{:02d}'.format(i), '10.100.0.{}'.format(i))
            for i in range(2,5)]

    broadcast_eth = 'ff:ff:ff:ff:ff:ff'
    broadcast_ip ='255.255.255.255'

    '''
    test case 1: receive ARP requests
    '''
    # arp request from net0
    pkt1 = create_ip_arp_request(hosts0[0].eth_addr, hosts0[0].ip_addr, intfs[0].ipaddr)
    s.expect(PacketInputEvent(intfs[0].name, pkt1, display=Arp), "ARP request for {} should arrive on {}".format(intfs[0].ipaddr, intfs[0].name))
    pkt2 = create_ip_arp_reply(intfs[0].ethaddr, hosts0[0].eth_addr, intfs[0].ipaddr, hosts0[0].ip_addr)
    s.expect(PacketOutputEvent(intfs[0].name, pkt2, display=Arp), "Router should send ARP reply for {} on {}".format(intfs[0].ipaddr, intfs[0].name))
    # the router should know hosts0[0]'s mac address
    pkt3 = mk_pkt(hosts1[0].eth_addr, intfs[1].ethaddr, hosts1[0].ip_addr, hosts0[0].ip_addr)
    s.expect(PacketInputEvent(intfs[1].name, pkt3, display=IPv4), "IP packet to be forward to {} should arrive on {}".format(hosts0[1].ip_addr, intfs[1].name))
    pkt4 = mk_pkt(intfs[0].ethaddr, hosts0[0].eth_addr, hosts1[0].ip_addr, hosts0[0].ip_addr, ttl=31)
    s.expect(PacketOutputEvent(intfs[0].name, pkt4, display=IPv4), "Router should forward IP packet to {} on {}".format(hosts0[0].ip_addr, intfs[0].name))

    '''
    test case 2: broadcast ARP req and forward IP packets
    '''
    pkt5 = mk_pkt(hosts0[0].eth_addr, intfs[0].ethaddr, hosts0[0].ip_addr, hosts1[1].ip_addr)
    s.expect(PacketInputEvent(intfs[0].name, pkt5, display=IPv4), "IP packet to be forward to {} should arrive on {}".format(hosts1[1].ip_addr, intfs[0].name))
    # broadcast
    pkt6 = create_ip_arp_request(intfs[1].ethaddr, intfs[1].ipaddr, hosts1[1].ip_addr)
    s.expect(PacketOutputEvent(intfs[1].name, pkt6, display=Arp), "Router should send ARP request for {} on {}".format(hosts1[1].ip_addr, intfs[1].name))
    # another pkt5 comes
    pkt7 = mk_pkt(hosts0[0].eth_addr, intfs[0].ethaddr, hosts0[0].ip_addr, hosts1[1].ip_addr)
    s.expect(PacketInputEvent(intfs[0].name, pkt7, display=IPv4), "IP packet to be forward to {} should arrive on {}".format(hosts1[1].ip_addr, intfs[0].name))
    # another pkt with dst = hosts1[1].ip_addr comes from eth2
    pkt8 = mk_pkt(hosts2[0].eth_addr, intfs[2].ethaddr, hosts2[0].ip_addr, hosts1[1].ip_addr)
    s.expect(PacketInputEvent(intfs[2].name, pkt8, display=IPv4), "IP packet to be forward to {} should arrive on {}".format(hosts1[1].ip_addr, intfs[2].name))
    # now the router receive the ARP reply from hosts1[1]
    pkt9 = create_ip_arp_reply(hosts1[1].eth_addr, intfs[1].ethaddr, hosts1[1].ip_addr, intfs[1].ipaddr)
    s.expect(PacketInputEvent(intfs[1].name, pkt9, display=Arp), "Router should receive ARP response for {} on {}".format(hosts1[1].ip_addr, intfs[1].name))
    # now the router should sends all buffered packets
    pkt10 = mk_pkt(intfs[1].ethaddr, hosts1[1].eth_addr, hosts0[0].ip_addr, hosts1[1].ip_addr, ttl=31)
    s.expect(PacketOutputEvent(intfs[1].name, pkt10, display=IPv4), "IP packet should be forwarded to {} on {}".format(hosts1[1].ip_addr, intfs[1].name))
    s.expect(PacketOutputEvent(intfs[1].name, pkt10, display=IPv4), "IP packet should be forwarded to {} on {}".format(hosts1[1].ip_addr, intfs[1].name))
    pkt11 = mk_pkt(intfs[1].ethaddr, hosts1[1].eth_addr, hosts2[0].ip_addr, hosts1[1].ip_addr, ttl=31)
    s.expect(PacketOutputEvent(intfs[1].name, pkt11, display=IPv4), "IP packet should be forwarded to {} on {}".format(hosts1[1].ip_addr, intfs[1].name))


    '''
    test case 3: forward to another router
    '''
    pkt12 = mk_pkt(hosts0[0].eth_addr, intfs[0].ethaddr, hosts0[0].ip_addr, hosts4[0].ip_addr)
    s.expect(PacketInputEvent(intfs[0].name, pkt12, display=IPv4), "IP packet to be forward to {} should arrive on {}".format(hosts4[0].ip_addr, intfs[0].name))
    # broadcast
    pkt13 = create_ip_arp_request(intfs[1].ethaddr, intfs[1].ipaddr, '10.10.0.254')
    s.expect(PacketOutputEvent(intfs[1].name, pkt13, display=Arp), "Router should send ARP request for {} on {}".format(hosts4[0].ip_addr, intfs[1].name))

    pkt14 = mk_pkt(hosts0[1].eth_addr, intfs[0].ethaddr, hosts0[1].ip_addr, hosts5[1].ip_addr)
    s.expect(PacketInputEvent(intfs[0].name, pkt14, display=IPv4), "IP packet to be forward to {} should arrive on {}".format(hosts5[1].ip_addr, intfs[0].name))
    # broadcast
    pkt15 = create_ip_arp_request(intfs[1].ethaddr, intfs[1].ipaddr, '10.10.1.254')
    s.expect(PacketOutputEvent(intfs[1].name, pkt15, display=Arp), "Router should send ARP request for {} on {}".format(hosts5[1].ip_addr, intfs[1].name))
    # reply
    pkt16 = create_ip_arp_reply('30:00:00:00:00:06', intfs[1].ethaddr, '10.10.1.254', intfs[1].ipaddr)
    s.expect(PacketInputEvent(intfs[1].name, pkt16, display=Arp), "Router should receive ARP response for {} on {}".format('10.10.1.254', intfs[1].name))
    pkt17 = mk_pkt(intfs[1].ethaddr, '30:00:00:00:00:06', hosts0[1].ip_addr, hosts5[1].ip_addr, ttl=31)
    s.expect(PacketOutputEvent(intfs[1].name, pkt17, display=IPv4), "Router should forward the packet to {} on {}".format(hosts5[1].ip_addr, intfs[1].name))

    pkt18 = create_ip_arp_reply('30:00:00:00:00:05', intfs[1].ethaddr, '10.10.0.254', intfs[1].ipaddr)
    s.expect(PacketInputEvent(intfs[1].name, pkt18, display=Arp), "Router should receive ARP response for {} on {}".format('10.10.0.254', intfs[1].name))
    pkt19 = mk_pkt(intfs[1].ethaddr, '30:00:00:00:00:05', hosts0[0].ip_addr, hosts4[0].ip_addr, ttl=31)
    s.expect(PacketOutputEvent(intfs[1].name, pkt19, display=IPv4), "Router should forward the packet to {} on {}".format(hosts4[0].ip_addr, intfs[1].name))

    '''
    test case 4: ARP does not response
    '''
    pkt20 = mk_pkt(hosts0[2].eth_addr, intfs[0].ethaddr, hosts0[2].ip_addr, hosts1[2].ip_addr)
    s.expect(PacketInputEvent(intfs[1].name, pkt20, display=IPv4), "IP packet to be forward to {} should arrive on {}".format(hosts1[2].ip_addr, intfs[1].name))
    pkt21 = create_ip_arp_request(intfs[1].ethaddr, intfs[1].ipaddr, hosts1[2].ip_addr)
    s.expect(PacketOutputEvent(intfs[1].name, pkt21, display=Arp), "Router should send ARP request for {} on {}".format(hosts1[2].ip_addr, intfs[1].name))
    # The ARP request is blocked, but other packets can go through
    s.expect(PacketInputTimeoutEvent(1), 'wait 1s.')
    s.expect(PacketOutputEvent(intfs[1].name, pkt21, display=Arp), "Router should send ARP request for {} on {} for the second time".format(hosts1[2].ip_addr, intfs[1].name))
    pkt22 = mk_pkt(hosts2[0].eth_addr, intfs[2].ethaddr, hosts2[0].ip_addr, hosts4[2].ip_addr)
    s.expect(PacketInputEvent(intfs[2].name, pkt22, display=IPv4), "IP packet to be forward to {} should arrive on {}".format(hosts4[2].ip_addr, intfs[2].name))
    pkt23 = mk_pkt(intfs[1].ethaddr, '30:00:00:00:00:05', hosts2[0].ip_addr, hosts4[2].ip_addr, ttl=31)
    s.expect(PacketOutputEvent(intfs[1].name, pkt23, display=IPv4), "Router should forward the packet to {} on {}".format(hosts4[2].ip_addr, intfs[1].name))
    for i in range(3):
        s.expect(PacketInputTimeoutEvent(1), 'wait 1s.')
        s.expect(PacketOutputEvent(intfs[1].name, pkt21, display=Arp), "Router should send ARP request for {} on {} for the {}th time".format(hosts1[2].ip_addr, intfs[1].name, i+3))
    s.expect(PacketInputTimeoutEvent(1), 'wait 1s.')

    # receive the ARP request, but too late to act
    pkt24 = create_ip_arp_reply(hosts1[2].eth_addr, intfs[1].ethaddr, hosts1[2].ip_addr, intfs[1].ipaddr)
    s.expect(PacketInputEvent(intfs[1].name, pkt24, display=Arp), "Router should receive ARP response for {} on {}".format(hosts1[2].ip_addr, intfs[1].name))

    '''
    test case 5: Packets intended for the Router
    '''
    pkt25 = mk_pkt(hosts0[2].eth_addr, intfs[0].ethaddr, hosts0[2].ip_addr, intfs[1].ipaddr, reply=True)
    s.expect(PacketInputEvent(intfs[0].name, pkt25, display=IPv4), "IP packet to be forward to {} should arrive on {}. This packet is intended for one interface of the router and should be dropped".format(hosts0[2].ip_addr, intfs[0].name))

    '''
    test case 6: Packets cannot find an out port in the forward table
    '''
    pkt26 = mk_pkt(hosts0[2].eth_addr, intfs[0].ethaddr, hosts0[2].ip_addr, '192.168.40.20')
    s.expect(PacketInputEvent(intfs[0].name, pkt26, display=IPv4), "IP packet to be forward to {} should arrive on {}. The destination ip addr is unknown and the packet should be dropped".format(hosts0[2].ip_addr, intfs[0].name))

    return s


scenario = ip_forwarding_tests()
