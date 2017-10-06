#!/usr/bin/env python3

from switchyard.lib.userlib import *
import time

def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt

def switch_lru_tests():
    s = TestScenario("timeout-based learning switch tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')
    s.add_interface('eth3', '10:00:00:00:00:04')

    hosts_eth = ['30:00:00:00:00:{:02d}'.format(i) for i in range(10)]
    hosts_ip = ['192.168.1.{}'.format(i+100) for i in range(10)]

    broadcast_eth = 'ff:ff:ff:ff:ff:ff'
    broadcast_ip ='255.255.255.255'

    '''
    test case 1: a simple LRU case
    eth0 h1 --> h4  :: eth1 eth2 eth3 | table={h1:(eth0,0)}
    eth1 h2 --> h1  :: eth0           | table={h1:(eth0,2),h2:(eth1,1)}
    eth2 h3 --> h1  :: eth0           | table={h1:(eth0,4),h2:(eth1,1),h3:(eth2,3)}
    eth3 h4 --> h1  :: eth0           | table={h1:(eth0,6),h2:(eth1,1),h3:(eth2,3),h4:(eth3,5)}
    eth2 h5 --> h1  :: eth0           | table={h1:(eth0,8),h2:(eth1,1),h3:(eth2,3),h4:(eth3,5),h5:(eth2,7)}
    eth3 h6 --> h7  :: eth0 eth1 eth2 | table={h1:(eth0,8),h3:(eth2,3),h4:(eth3,5),h5:(eth2,7),h6:(eth3,9)} // evict h2
    eth3 h4 --> h5  :: eth2           | table={h1:(eth0,8),h3:(eth2,3),h4:(eth3,5),h5:(eth2,10),h6:(eth3,9)}
    eth2 h5 --> h2  :: eth0 eth1 eth3 | table={h1:(eth0,8),h3:(eth2,3),h4:(eth3,5),h5:(eth2,10),h6:(eth3,9)} // cache miss
    '''
    pkt1 = mk_pkt(hosts_eth[1], hosts_eth[4], hosts_ip[1], hosts_ip[4])
    s.expect(PacketInputEvent("eth0", pkt1, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth0".format(hosts_eth[1], hosts_eth[2]))
    s.expect(PacketOutputEvent("eth1", pkt1, "eth2", pkt1, "eth3", pkt1, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth1, eth2 and eth3".format(hosts_eth[2]))

    pkt2 = mk_pkt(hosts_eth[2], hosts_eth[1], hosts_ip[2], hosts_ip[1])
    s.expect(PacketInputEvent("eth1", pkt2, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth1".format(hosts_eth[2], hosts_eth[1]))
    s.expect(PacketOutputEvent("eth0", pkt2, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0".format(hosts_eth[1]))

    pkt3 = mk_pkt(hosts_eth[3], hosts_eth[1], hosts_ip[3], hosts_ip[1])
    s.expect(PacketInputEvent("eth2", pkt3, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth2".format(hosts_eth[3], hosts_eth[1]))
    s.expect(PacketOutputEvent("eth0", pkt3, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0".format(hosts_eth[1]))

    pkt4 = mk_pkt(hosts_eth[4], hosts_eth[1], hosts_ip[4], hosts_ip[1])
    s.expect(PacketInputEvent("eth3", pkt4, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth3".format(hosts_eth[4], hosts_eth[1]))
    s.expect(PacketOutputEvent("eth0", pkt4, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0".format(hosts_eth[1]))

    pkt5 = mk_pkt(hosts_eth[5], hosts_eth[1], hosts_ip[5], hosts_ip[1])
    s.expect(PacketInputEvent("eth2", pkt5, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth2".format(hosts_eth[5], hosts_eth[1]))
    s.expect(PacketOutputEvent("eth0", pkt5, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0".format(hosts_eth[1]))

    pkt6 = mk_pkt(hosts_eth[6], hosts_eth[7], hosts_ip[6], hosts_ip[7])
    s.expect(PacketInputEvent("eth3", pkt6, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth3".format(hosts_eth[6], hosts_eth[7]))
    s.expect(PacketOutputEvent("eth0", pkt6, "eth1", pkt6, "eth2", pkt6, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0, eth1 and eth2".format(hosts_eth[7]))

    pkt7 = mk_pkt(hosts_eth[4], hosts_eth[5], hosts_ip[4], hosts_ip[5])
    s.expect(PacketInputEvent("eth3", pkt7, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth3".format(hosts_eth[4], hosts_eth[5]))
    s.expect(PacketOutputEvent("eth2", pkt7, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth2".format(hosts_eth[5]))

    pkt8 = mk_pkt(hosts_eth[5], hosts_eth[2], hosts_ip[5], hosts_ip[2])
    s.expect(PacketInputEvent("eth2", pkt8, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth3".format(hosts_eth[5], hosts_eth[2]))
    s.expect(PacketOutputEvent("eth0", pkt8, "eth1", pkt8, "eth3", pkt8, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0, eth1 and eth3".format(hosts_eth[2]))

    '''
    test case 2: multiple duplicate packets
    eth3 h4 --> h3 :: eth2 | table={h1:(eth0,8),h3:(eth2,11),h4:(eth3,5),h5:(eth2,10),h6:(eth3,9)}
    eth3 h4 --> h3 :: eth2 | table={h1:(eth0,8),h3:(eth2,12),h4:(eth3,5),h5:(eth2,10),h6:(eth3,9)}
    eth3 h4 --> h3 :: eth2 | table={h1:(eth0,8),h3:(eth2,13),h4:(eth3,5),h5:(eth2,10),h6:(eth3,9)}
    eth1 h2 --> h3 :: eth2 | table={h1:(eth0,8),h2:(eth1,14),h3:(eth2,15),h5:(eth2,10),h6:(eth3,9)} // evict h4
    eth1 h2 --> h4 :: eth0, eth2, eth3 | table={h1:(eth0,8),h2:(eth1,14),h3:(eth2,15),h5:(eth2,10),h6:(eth3,9)} // miss
    '''
    pkt9 = mk_pkt(hosts_eth[4], hosts_eth[3], hosts_ip[4], hosts_ip[3])
    for i in range(3):
        s.expect(PacketInputEvent("eth3", pkt9, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth3".format(hosts_eth[4], hosts_eth[3]))
        s.expect(PacketOutputEvent("eth2", pkt9, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth2".format(hosts_eth[3]))

    pkt10 = mk_pkt(hosts_eth[2], hosts_eth[3], hosts_ip[2], hosts_ip[3])
    s.expect(PacketInputEvent("eth1", pkt10, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth1".format(hosts_eth[2], hosts_eth[3]))
    s.expect(PacketOutputEvent("eth2", pkt10, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth2".format(hosts_eth[3]))

    pkt11 = mk_pkt(hosts_eth[2], hosts_eth[4], hosts_ip[2], hosts_ip[4])
    s.expect(PacketInputEvent("eth1", pkt11, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth1".format(hosts_eth[2], hosts_eth[4]))
    s.expect(PacketOutputEvent("eth0", pkt11, "eth2", pkt11, "eth3", pkt11, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0, eth2 and eth3".format(hosts_eth[4]))

    '''
    test case 3: packets with src the same as dst
    eth3 h6 --> h6 ::  | table={h1:(eth0,8),h2:(eth1,14),h3:(eth2,15),h5:(eth2,10),h6:(eth3,16)}
    eth3 h4 --> h2 :: eth1 | table={h2:(eth1,18),h3:(eth2,15),h4:(eth3,17),h5:(eth2,10),h6:(eth3,16)}  // evict 1
    eth2 h3 --> h1 :: eth0, eth1, eth3 | table={h2:(eth1,18),h3:(eth2,15),h4:(eth3,17),h5:(eth2,10),h6:(eth3,16)} // miss
    '''
    pkt12 = mk_pkt(hosts_eth[6], hosts_eth[6], hosts_ip[6], hosts_ip[6])
    s.expect(PacketInputEvent("eth3", pkt12, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth3".format(hosts_eth[6], hosts_eth[6]))
    s.expect(PacketOutputEvent("eth3", pkt12, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth1".format(hosts_eth[6]))

    pkt13 = mk_pkt(hosts_eth[4], hosts_eth[2], hosts_ip[4], hosts_ip[2])
    s.expect(PacketInputEvent("eth3", pkt13, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth3".format(hosts_eth[4], hosts_eth[2]))
    s.expect(PacketOutputEvent("eth1", pkt13, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth1".format(hosts_eth[2]))

    pkt14 = mk_pkt(hosts_eth[3], hosts_eth[1], hosts_ip[3], hosts_ip[1])
    s.expect(PacketInputEvent("eth2", pkt14, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth2".format(hosts_eth[3], hosts_eth[1]))
    s.expect(PacketOutputEvent("eth0", pkt14, "eth1", pkt14, "eth3", pkt14, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0, eth1 and eth3".format(hosts_eth[1]))

    '''
    test case 4: broadcast
    eth0 h1 --> broadcast :: eth1, eth2, eth3 | table={h1:(eth0,19),h2:(eth1,18),h3:(eth2,15),h4:(eth3,17),h6:(eth3,16)} // evict h5
    eth2 h5 --> broadcast :: eth0, eth1, eth3 | table={h1:(eth0,19),h2:(eth1,18),h4:(eth3,17),h5:(eth2,20),h6:(eth3,16)} // evict h3
    '''
    pkt15 = mk_pkt(hosts_eth[1], broadcast_eth, hosts_ip[1], broadcast_ip)
    s.expect(PacketInputEvent("eth0", pkt15, display=Ethernet), "A broadcast Ethernet frame should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", pkt15, "eth2", pkt15, "eth3", pkt15, display=Ethernet), "The broadcast Ethernet frame should be forwarded out ports eth1, eth2 and eth3")

    pkt16 = mk_pkt(hosts_eth[5], broadcast_eth, hosts_ip[5], broadcast_ip)
    s.expect(PacketInputEvent("eth2", pkt16, display=Ethernet), "A broadcast Ethernet frame should arrive on eth2")
    s.expect(PacketOutputEvent("eth0", pkt16, "eth1", pkt16, "eth3", pkt16, display=Ethernet), "The broadcast Ethernet frame should be forwarded out ports eth0, eth1 and eth3")

    '''
    test case 5: the dst is one of the switch's ports
    eth0 h1 --> eth0 :: | table={h1:(eth0,21),h2:(eth1,18),h4:(eth3,17),h5:(eth2,20),h6:(eth3,16)}
    eth3 h4 --> eth0 :: | table={h1:(eth0,21),h2:(eth1,18),h4:(eth3,22),h5:(eth2,20),h6:(eth3,16)}
    '''
    pkt17 = mk_pkt(hosts_eth[1], '10:00:00:00:00:01', hosts_ip[1], '172.16.42.2')
    s.expect(PacketInputEvent("eth0", pkt17, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth0".format(hosts_eth[1], '10:00:00:00:00:01'))
    pkt18 = mk_pkt(hosts_eth[4], '10:00:00:00:00:01', hosts_ip[1], '172.16.42.2')
    s.expect(PacketInputEvent("eth3", pkt18, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth3".format(hosts_eth[4], '10:00:00:00:00:01'))

    '''
    test case 6: topology change
    eth0 h6 --> h4 :: eth3 | table={h1:(eth0,21),h2:(eth1,18),h4:(eth3,23),h5:(eth2,20),h6:(eth0,16)}
    eth2 h2 --> h6 :: eth0 | table={h1:(eth0,21),h2:(eth2,18),h4:(eth3,23),h5:(eth2,20),h6:(eth0,24)}
    eth1 h3 --> h5 :: eth2 | table={h1:(eth0,21),h3:(eth1,25),h4:(eth3,23),h5:(eth2,26),h6:(eth0,24)}  // evict h2
    eth1 h3 --> h2 :: eth0, eth2, eth3 | table={h1:(eth0,21),h3:(eth1,25),h4:(eth3,23),h5:(eth2,26),h6:(eth0,24)}
    '''
    pkt19 = mk_pkt(hosts_eth[6], hosts_eth[4], hosts_ip[6], hosts_ip[4])
    s.expect(PacketInputEvent("eth0", pkt19, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth0".format(hosts_eth[6], hosts_eth[4]))
    s.expect(PacketOutputEvent("eth3", pkt19, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth3".format(hosts_eth[4]))

    pkt20 = mk_pkt(hosts_eth[2], hosts_eth[6], hosts_ip[2], hosts_ip[6])
    s.expect(PacketInputEvent("eth2", pkt20, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth2".format(hosts_eth[2], hosts_eth[6]))
    s.expect(PacketOutputEvent("eth0", pkt20, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0".format(hosts_eth[6]))

    pkt21 = mk_pkt(hosts_eth[3], hosts_eth[5], hosts_ip[3], hosts_ip[5])
    s.expect(PacketInputEvent("eth1", pkt21, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth1".format(hosts_eth[3], hosts_eth[5]))
    s.expect(PacketOutputEvent("eth2", pkt21, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth2".format(hosts_eth[5]))

    pkt22 = mk_pkt(hosts_eth[3], hosts_eth[2], hosts_ip[3], hosts_ip[2])
    s.expect(PacketInputEvent("eth1", pkt22, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth1".format(hosts_eth[3], hosts_eth[2]))
    s.expect(PacketOutputEvent("eth0", pkt22, "eth2", pkt22, "eth3", pkt22, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0, eth2 and eth3".format(hosts_eth[2]))
    return s


scenario = switch_lru_tests()
