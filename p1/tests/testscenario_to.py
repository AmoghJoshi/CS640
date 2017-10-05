#!/usr/bin/env python3

'''
h1 ... h10   h[i] = "30:00:00:00:00:0i"
eth0 eth1 eth2 eth3   eth[i] = "10:00:00:00:00:i"
simple case

broadcast
0s    eth0 h1 --> h2    // eth1 eth2 eth3
      eth1 h2 --> h1    // eth0
      eth0 h1 --> h4    // eth1 eth2 eth3
1s    eth3 h3 --> b     // eth0 eth1 eth2
10s   eth2 h5 --> h3    // eth3
11.5s eth0 h1 --> h3    // eth1 eth2 eth3

intended for switch
0s    eth0 h1 --> eth1  // nop
1s    eth1 h2 --> h1    // eth0

topology change
0s    eth0 h1 --> h2    // eth1 eth2 eth3
2s    eth1 h2 --> h1    // eth0
3s    eth2 h1 --> h3    // eth0 eth2 eth3
5s    eth1 h2 --> h1    // eth2
10.5s eth3 h3 --> h1    // eth0 eth1 eth2
'''

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

def switch_to_tests():
    s = TestScenario("timeout-based learning switch tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')
    s.add_interface('eth3', '10:00:00:00:00:04')

    hosts_eth = ['30:00:00:00:00:{:02d}'.format(i) for i in range(10)]
    hosts_ip = ['172.16.42.{}'.format(i) for i in range(10)]

    '''
    test case 1: a simple timeout case
        0s    eth0 h1 --> h2   // eth1 eth2 eth3
        8s    eth1 h2 --> h1   // eth0
        10.5s eth1 h2 --> h1   // eth0 eth2 eth3
    '''
    pkt1 = mk_pkt(hosts_eth[1], hosts_eth[2], hosts_ip[1], hosts_ip[2])
    s.expect(PacketInputEvent("eth0", pkt1, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth0".format(hosts_eth[1], hosts_eth[2]))
    s.expect(PacketOutputEvent("eth1", pkt1, "eth2", pkt1, "eth3", pkt1, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth1, eth2 and eth3".format(hosts_eth[2]))

    time.sleep(1)   # 1s
    pkt2 = mk_pkt(hosts_eth[2], hosts_eth[1], hosts_ip[2], hosts_ip[1])
    s.expect(PacketInputEvent("eth1", pkt2, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth1".format(hosts_eth[2], hosts_eth[1]))
    s.expect(PacketOutputEvent("eth0", pkt2, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0".format(hosts_eth[1]))

    time.sleep(10.5) # 10.5s
    s.expect(PacketInputEvent("eth1", pkt2, display=Ethernet), "An Ethernet frame ({} -> {}) should arrive on eth1".format(hosts_eth[2], hosts_eth[1]))
    s.expect(PacketOutputEvent("eth0", pkt2, "eth2", pkt2, "eth3", pkt2, display=Ethernet), "The Ethernet frame destined to {} should be forwarded out ports eth0, eth2 and eth3".format(hosts_eth[1]))

    '''
    # test case 2: a frame with any unicast address except one assigned to hub
    # interface should be sent out all ports except ingress
    reqpkt = mk_pkt("20:00:00:00:00:01", "30:00:00:00:00:02", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "An Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet), "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")

    resppkt = mk_pkt("30:00:00:00:00:02", "20:00:00:00:00:01", '172.16.42.2', '192.168.1.100', reply=True)
    s.expect(PacketInputEvent("eth1", resppkt, display=Ethernet), "An Ethernet frame from 30:00:00:00:00:02 to 20:00:00:00:00:01 should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", resppkt, "eth2", resppkt, display=Ethernet), "Ethernet frame destined to 20:00:00:00:00:01 should be flooded out eth0 and eth2")

    # test case 3: a frame with dest address of one of the interfaces should
    # result in nothing happening
    reqpkt = mk_pkt("20:00:00:00:00:01", "10:00:00:00:00:03", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet), "An Ethernet frame should arrive on eth2 with destination address the same as eth2's MAC address")
    s.expect(PacketInputTimeoutEvent(1.0), "The hub should not do anything in response to a frame arriving with a destination address referring to the hub itself.")
    '''
    return s

scenario = switch_to_tests()
