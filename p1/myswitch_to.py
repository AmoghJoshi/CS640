'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import threading


class ForwardTable(object):
    LIFESPAN=10

    def __init__(self):
        self._lock = threading.Lock()
        self._table = dict()   # (key, (intf, timeout))

    def insert(self, ethaddr, intf_name):
        self._lock.acquire()
        if ethaddr in self._table:
            self._table[ethaddr][1].cancel()
        self._table[ethaddr] = (intf_name, threading.Timer(ForwardTable.LIFESPAN, self.remove, (ethaddr,)) )
        self._table[ethaddr][1].start()
        self._lock.release()

    def remove(self, ethaddr):
        self._lock.acquire()
        self._table.pop(ethaddr)
        self._lock.release()

    def lookup(self, ethaddr):
        if ethaddr in self._table:
            return self._table[ethaddr][0]
        else:
            return None


def main(net):
    forward_table = ForwardTable()
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
            forward_table.insert(packet[0].src, input_port);
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {} (ts={})".format(net.name, packet, input_port, timestamp))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            output_port = forward_table.lookup(packet[0].dst)
            if output_port is not None:
                log_debug ("Send packet {} to {}".format(packet, output_port))
                net.send_packet(output_port, packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
