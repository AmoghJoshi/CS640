'''
Ethernet learning switch in Python.

This file implements a traffic-volume based learning switch.
'''
from switchyard.lib.userlib import *

def main(net):

    # initialize forwarding table: [src, port, traffic_volume]
    forwarding_table = []
    forwarding_table_capacity = 5

    # retrieve Interface objects for the current node
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces] # all related Ethernet addresses

    # add some informational text about ports on this device
    log_info ("Switch is starting up with these ports:")
    for port in net.ports():
        log_info ("{}: ethernet address {}".format(port.name, port.ethaddr))

    # core functionalities
    while True:
        try:
            timestamp, input_port, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))

        # first packet
        #if len(forwarding_table) == 0:
        #    forwarding_table.append([packet[0].src, input_port, 0])

        # special case 1: dst is broadcast address
        if str.lower(packet[0].dst.toStr()) == "ff:ff:ff:ff:ff:ff":
            log_info ("Packet intended for broadcast")
            log_info ("Flooding packet out all ports except input port")
            for intf in my_interfaces:
                if  intf.name != input_port:
                    log_debug ("Flooding packet {} to port {}".format(packet, intf.name))
                    net.send_packet(intf, packet)
            continue

        # special case 2: ignore the packet if destined for the switch itself
        if packet[0].dst in mymacs:
            log_info ("Packet intended for me")
            log_info ("Do nothing")
            continue

        log_info ("Packet not intended for me")

        # general case: follow the traffic_flow.jpg logistic
        srclist = [item[0] for item in forwarding_table]
        if packet[0].src in srclist: # table contains entry for src address
            id_entry = srclist.index(packet[0].src)
            port_in_table = forwarding_table[id_entry][1]
            if input_port != port_in_table:
                forwarding_table[id_entry][1] = input_port
        else:
            if len(forwarding_table) < forwarding_table_capacity:
                forwarding_table.append([packet[0].src, input_port, 0])
            else: # table is full
                forwarding_table.sort(key=lambda item: item[2])
                del forwarding_table[0]
                forwarding_table.append([packet[0].src, input_port, 0])

        # entry for destination exists in table?
        srclist = [item[0] for item in forwarding_table]
        if packet[0].dst in srclist: # yes
            id_entry = srclist.index(packet[0].dst)
            forwarding_table[id_entry][2] += 1
            net.send_packet(forwarding_table[id_entry][1], packet)
        else: # no
            # find the dst, flood to this port only
            # flag = False
            for intf in my_interfaces:
                if  intf.name != input_port:
                    # flag = True
                    log_info ("Output port found")
                    log_info ("Flooding packet {} to learned port {}".format(packet, intf.name))
                    net.send_packet(intf, packet)
            # not find the dst from interfaces, flood to all ports except input port
            #if flag == False:
            #    log_info ("Output port not found")
            #    log_info ("Flooding packet out all ports except input port")
            #    for intf in my_interfaces:
            #        if  intf.name != input_port:
            #            log_debug ("Flooding packet {} to port {}".format(packet, intf.name))
            #            net.send_packet(intf, packet)


    # shut down the switch when Shutdown exception is triggered
    net.shutdown()

