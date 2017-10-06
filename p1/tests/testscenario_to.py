#!/usr/bin/env python3


from switchyard.lib.userlib import *

def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt

def switch_to_tests():
    s = TestScenario("timeout-based learning switch tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')
    s.add_interface('eth3', '10:00:00:00:00:04')

    hosts_eth = ['30:00:00:00:00:{:02d}'.format(i) for i in range(10)]
    hosts_ip = ['192.168.1.{}'.format(100+i) for i in range(10)]

    broadcast_eth = 'ff:ff:ff:ff:ff:ff'
    broadcast_ip ='255.255.255.255'

    '''
    test case 1: a simple timeout case
        0s    eth0 h1 --> h2 :: eth1 eth2 eth3 | table={(h1, eth0, 0)}
        1.5s  eth1 h2 --> h1 :: eth0           | table={(h1, eth0, 0), (h2, eth1, 1.5)}
        10.5s eth1 h2 --> h1 :: eth0 eth2 eth3 | table={(h2, eth1, 10.5)}
    '''
    pkt1 = mk_pkt(hosts_eth[1], hosts_eth[2], hosts_ip[1], hosts_ip[2])
    s.expect(PacketInputEvent("eth0", pkt1, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth0".format(hosts_eth[1], hosts_eth[2]))
    s.expect(PacketOutputEvent("eth1", pkt1, "eth2", pkt1, "eth3", pkt1, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth1, eth2 and eth3".format(hosts_eth[2]))

    s.expect(PacketInputTimeoutEvent(1.5), 'wait 1.5s (1.5s)')
    pkt2 = mk_pkt(hosts_eth[2], hosts_eth[1], hosts_ip[2], hosts_ip[1])
    s.expect(PacketInputEvent("eth1", pkt2, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth1".format(hosts_eth[2], hosts_eth[1]))
    s.expect(PacketOutputEvent("eth0", pkt2, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0".format(hosts_eth[1]))

    s.expect(PacketInputTimeoutEvent(9), 'wait 9s (10.5s)')
    s.expect(PacketInputEvent("eth1", pkt2, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth1".format(hosts_eth[2], hosts_eth[1]))
    s.expect(PacketOutputEvent("eth0", pkt2, "eth2", pkt2, "eth3", pkt2, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0, eth2 and eth3".format(hosts_eth[1]))

    '''
    test case 2: broadcast
        10.5s eth2 h3 --> h1 :: eth0 eth1 eth3 | table={(h2, eth1, 10.5), (h3, eth2, 10.5)}
              eth0 h1 --> b  :: eth1 eth2 eth3 | table={(h2, eth1, 10.5), (h3, eth2, 10.5), (h1, eth0, 10.5)}
    '''
    pkt3 = mk_pkt(hosts_eth[3], hosts_eth[1], hosts_ip[3], hosts_ip[1])
    s.expect(PacketInputEvent("eth2", pkt3, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth2".format(hosts_eth[3], hosts_eth[1]))
    s.expect(PacketOutputEvent("eth0", pkt3, "eth1", pkt3, "eth3", pkt3, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0, eth1 and eth3".format(hosts_eth[1]))

    pkt4 = mk_pkt(hosts_eth[1], broadcast_eth, hosts_ip[1], broadcast_ip)
    s.expect(PacketInputEvent("eth0", pkt4, display=Ethernet), "A broadcast Ethernet frame should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", pkt4, "eth2", pkt4, "eth3", pkt4, display=Ethernet), "The broadcast Ethernet frame should be forwarded out ports eth1, eth2 and eth3")

    '''
    test case 3: intended for switch
        12s    eth0 h1 --> eth1 :: | table={(h2, eth1, 10.5), (h3, eth2, 10.5), (h1, eth0, 12)}
    '''
    s.expect(PacketInputTimeoutEvent(1.5), 'wait 1.5s (12s)')
    pkt5 = mk_pkt(hosts_eth[1], '10:00:00:00:00:02', hosts_ip[1], '172.16.42.2')
    s.expect(PacketInputEvent("eth0", pkt5, display=Ethernet), "A Ethernet frame for the switch should arrive on eth0")

    '''
    test case 4: topology change
        15s   eth3 h1 --> h2 :: eth1 | table={(h2, eth1, 10.5), (h3, eth2, 10.5), (h1, eth3, 15)}
        21s   eth0 h2 --> h3 :: eth1, eth2, eth3 | table={(h2, eth0, 21), (h1, eth3, 15)}
        24s   eth0 h2 --> h1 :: eth3 | table={(h2, eth0, 24), (h1, eth3, 15)}
        26s   eth0 h2 --> h1 :: eth1, eth2, eth3 | table={(h2, eth0, 26)}
    '''
    s.expect(PacketInputTimeoutEvent(3), 'wait 3s (15s)')
    pkt6 = mk_pkt(hosts_eth[1], hosts_eth[2], hosts_ip[1], hosts_ip[2])
    s.expect(PacketInputEvent("eth3", pkt6, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth2".format(hosts_eth[1], hosts_eth[2]))
    s.expect(PacketOutputEvent("eth1", pkt6, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth1".format(hosts_eth[2]))

    s.expect(PacketInputTimeoutEvent(6), 'wait 6s (21s)')
    pkt6 = mk_pkt(hosts_eth[2], hosts_eth[3], hosts_ip[2], hosts_ip[3])
    s.expect(PacketInputEvent("eth0", pkt6, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth0".format(hosts_eth[2], hosts_eth[3]))
    s.expect(PacketOutputEvent("eth1", pkt6, "eth2", pkt6, "eth3", pkt6, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth1, eth2 and eth3".format(hosts_eth[3]))

    s.expect(PacketInputTimeoutEvent(3), 'wait 3s (24s)')
    pkt7 = mk_pkt(hosts_eth[2], hosts_eth[1], hosts_ip[2], hosts_ip[1])
    s.expect(PacketInputEvent("eth0", pkt7, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth0".format(hosts_eth[2], hosts_eth[1]))
    s.expect(PacketOutputEvent("eth3", pkt7, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth3".format(hosts_eth[1]))

    s.expect(PacketInputTimeoutEvent(2), 'wait 2s (26s)')
    pkt8 = mk_pkt(hosts_eth[2], hosts_eth[1], hosts_ip[2], hosts_ip[1])
    s.expect(PacketInputEvent("eth0", pkt8, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth0".format(hosts_eth[2], hosts_eth[1]))
    s.expect(PacketOutputEvent("eth1", pkt8, "eth2", pkt8, "eth3", pkt8, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth1, eth2 and eth3".format(hosts_eth[1]))

    return s

scenario = switch_to_tests()
