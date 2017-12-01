#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.logging import *
from queue import Queue
from random import randint
import time

def read_arguments(path):
    with open(path, 'r') as f:
        text = f.read()
    args = text.split()
    assert len(args) == 12
    opts = {}
    for i in range(0, 12, 2):
        if args[i] == '-b':
            opts['blastee_ip'] = args[i+1]
        elif args[i] == '-n':
            opts['num_pkts'] = int(args[i+1])
            assert opts['num_pkts'] >= 0
        elif args[i] == '-l':
            opts['length'] = int(args[i+1])
            assert opts['length'] >= 0 and opts['length'] <= 65535
        elif args[i] == '-w':
            opts['window'] = int(args[i+1])
            assert opts['window'] > 0
        elif args[i] == '-t':
            opts['timeout'] = float(args[i+1]) * 0.001
            assert opts['timeout'] > 0
        elif args[i] == '-r':
            opts['recv_timeout'] = float(args[i+1]) * 0.001
            assert opts['recv_timeout'] > 0
    return opts

def unpack_ack_bytes(data):
    seq_num = int.from_bytes(data[0:4], byteorder='big')
    payload = data[4:].decode('utf-8', 'ignore')
    return seq_num, payload

def pack_data_bytes(seq_num, payload):
    seq_bytes = seq_num.to_bytes(4, byteorder='big')
    payload_bytes = payload.encode('utf-8', 'ignore')
    length_bytes = len(payload_bytes).to_bytes(2, byteorder='big')
    return seq_bytes + length_bytes + payload_bytes

def switchy_main(net):
    start_time = time.time()
    num_reTx, num_coarse_timeout = 0, 0
    size_Tx, size_good_Tx = 0, 0
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    opts = read_arguments('blaster_params.txt')

    mac_mapping = {'middlebox-eth0': '40:00:00:00:00:01'}

    pending_pkts_map = {}
    retranmit_queue = Queue()
    LHS = 1     # next pkt to ack
    RHS = 1     # next pkt to send
    time_lhs_stuck = time.time()
    while LHS < opts['num_pkts'] + 1:
        sentpkt = False
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            timestamp,dev,pkt = net.recv_packet(timeout=opts['recv_timeout'])
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet {}".format(pkt))
            if pkt.num_headers() < 4 or type(pkt[1]) is not IPv4 or type(pkt[2]) is not UDP or type(pkt[3]) is not RawPacketContents:
                continue

            bytes_data = pkt[3].to_bytes()
            seq_num, payload = unpack_ack_bytes(bytes_data)
            log_info("I got an ack seq num={}".format(seq_num))
            print('stats:')
            total_time = time.time() - start_time
            print('Total TX time (seconds): {}'.format(total_time))
            print('Number of reTx: {}'.format(num_reTx))
            print('Number of coarse TOs: {}'.format(num_coarse_timeout))
            print('Throughput (Bps): {}'.format(size_Tx / total_time))
            print('Goodput (Bps): {}'.format(size_good_Tx / total_time))
            if seq_num in pending_pkts_map:
                del pending_pkts_map[seq_num]
            old_LHS = LHS
            LHS = min(pending_pkts_map.keys()) if len(pending_pkts_map) > 0 else RHS
            if old_LHS < LHS:
                time_lhs_stuck = time.time()

        else:
            log_debug("Didn't receive anything")
            current_time = time.time()
            if time_lhs_stuck + opts['timeout'] < current_time:
                num_coarse_timeout += 1
                log_debug('timeout happens at {}. number of coarse TOs = {}'.format(current_time, num_coarse_timeout))
                time_lhs_stuck = current_time
                # enqueue all pending packets
                kvs = sorted(pending_pkts_map.items())
                for k, v in kvs:
                    retranmit_queue.put(k)

            seqnum = -1
            while retranmit_queue.qsize() > 0 and seqnum not in pending_pkts_map:
                seqnum = retranmit_queue.get()
            if seqnum in pending_pkts_map:
                retx_pkt = pending_pkts_map[seqnum]
                log_debug("retransmit packet seqnum={}".format(seqnum))
                size_Tx += len(retx_pkt[3].to_bytes())
                num_reTx += 1
                net.send_packet("blaster-eth0", pending_pkts_map[seqnum])
                sentpkt = True

            log_debug('resent packet={}, RHS = {}, LHS = {}'.format(sentpkt, RHS, LHS))
            if not sentpkt and RHS + 1 - LHS <= opts['window'] and RHS <= opts['num_pkts']:
                '''
                Creating the headers for the packet
                '''
                eth_hdr = Ethernet(src=mymacs[0], dst=mac_mapping['middlebox-eth0'],
                        ethertype=EtherType.IP)
                ip_hdr = IPv4(src=myips[0], dst=opts['blastee_ip'], protocol=IPProtocol.UDP, ttl=64)
                udp_hdr = UDP(src=8080, dst=80)
                contents_hdr = RawPacketContents(pack_data_bytes(RHS, 'a' * opts['length']))
                size_Tx += len(contents_hdr.to_bytes())
                size_good_Tx += len(contents_hdr.to_bytes())
                pkt = eth_hdr + ip_hdr + udp_hdr + contents_hdr
                '''
                Do other things here and send packet
                '''
                pending_pkts_map[RHS] = pkt
                RHS += 1
                net.send_packet("blaster-eth0", pkt)
                log_debug("send packet seqnum={}".format(RHS-1))

    log_debug('exiting. LHS={}, RHS={}'.format(LHS, RHS))
    net.shutdown()
