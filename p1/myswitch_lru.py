'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import threading


class ForwardTable(object):
    CAPACITY=5

    def __init__(self):
        self._table = dict()   # (key, (intf, timeout))

    def insert(self, ethaddr, intf_name, timestamp):
        if ethaddr in self._table:
            self._table[ethaddr][0] = intf_name
            log_debug("FWT: modify entry ({},({},{}))".format(ethaddr, intf_name, timestamp))
        else:
            if len(self._table) == ForwardTable.CAPACITY:
                entry_to_remove = min(self._table.items(), key=lambda entry : entry[1][1])
                self._table.pop(entry_to_remove[0])
                log_debug("FWT: table size reaches {}, pop entry {}".format(ForwardTable.CAPACITY, entry_to_remove))
            self._table[ethaddr] = (intf_name, timestamp)
            log_debug("FWT: insert entry ({},({},{}))".format(ethaddr, intf_name, timestamp))

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
            forward_table.insert(packet[0].src, input_port, timestamp);
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
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
