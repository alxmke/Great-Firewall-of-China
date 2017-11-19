#!/usr/bin/env python

import time
import threading
from scapy.all import *
import sys
import socket
import json
import Queue
import interfaces

maxhop = 25

# A request that will trigger the great firewall but will NOT cause
# the web server to process the connection.  You probably want it here

triggerfetch = "GET /search?q=falun=gong HTTP/1.1\r\nCONNECTION: keep-alive\r\nHOST: www.google.com\r\n\r\n"

# A couple useful functions that take scapy packets
def isRST(packet):
    return (TCP in packet) and (packet[IP][TCP].flags & 0x4 != 0)

def isICMP(packet):
    return ICMP in packet

def isTimeExceeded(packet):
    return ICMP in packet and packet[IP][ICMP].type == 11

# A general python object to handle a lot of this stuff...
#
# Use this to implement the actual functions you need.
class PacketUtils:
    def __init__(self, dst=None):
        # Get one's SRC IP & interface
        i = interfaces.interfaces()
        self.src = i[1][0]
        self.iface = i[0]
        self.netmask = i[1][1]
        self.enet = i[2]
        self.dst = dst
        sys.stderr.write("SIP IP %s, iface %s, netmask %s, enet %s\n" %
                         (self.src, self.iface, self.netmask, self.enet))
        # A queue where received packets go.  If it is full
        # packets are dropped.
        self.packetQueue = Queue.Queue(100000)
        self.dropCount = 0
        self.idcount = 0

        self.ethrdst = ""

        # Get the destination ethernet address with an ARP
        self.arp()
        
        # You can add other stuff in here to, e.g. keep track of
        # outstanding ports, etc.
        
        # Start the packet sniffer
        t = threading.Thread(target=self.run_sniffer)
        t.daemon = True
        t.start()
        time.sleep(.1)

    # generates an ARP request
    def arp(self):
        e = Ether(dst="ff:ff:ff:ff:ff:ff",
                  type=0x0806)
        gateway = ""
        srcs = self.src.split('.')
        netmask = self.netmask.split('.')
        for x in range(4):
            nm = int(netmask[x])
            addr = int(srcs[x])
            if x == 3:
                gateway += "%i" % ((addr & nm) + 1)
            else:
                gateway += ("%i" % (addr & nm)) + "."
        sys.stderr.write("Gateway %s\n" % gateway)
        a = ARP(hwsrc=self.enet,
                pdst=gateway)
        packet = srp1([e/a], iface=self.iface, verbose=0)
        self.etherdst = packet[Ether].src
        sys.stderr.write("Ethernet destination %s\n" % (self.etherdst))


    # A function to send an individual packet.
    def send_packet(self, payload=None, ttl=32, flags="",
                 seq=None, ack=None,
                 sport=None, dport=80,ipid=None,
                 dip=None,debug=False):
        if sport == None:
            sport = random.randint(1024, 32000)
        if seq == None:
            seq = random.randint(1, 31313131)
        if ack == None:
            ack = random.randint(1, 31313131)
        if ipid == None:
            ipid = self.idcount
            self.idcount += 1
        t = TCP(sport=sport, dport=dport,
                flags=flags, seq=seq, ack=ack)
        ip = IP(src=self.src,
                dst=self.dst,
                id=ipid,
                ttl=ttl)
        packet = ip/t
        if payload:
            packet = ip/t/payload
        else:
            pass
        e = Ether(dst=self.etherdst,
                  type=0x0800)
        # Have to send as Ethernet to avoid interface issues
        sendp([e/packet], verbose=1, iface=self.iface)
        # Limit to 20 PPS.
        time.sleep(.05)
        # And return the packet for reference
        return packet


    # Has an automatic 5 second timeout.
    def get_packet(self, timeout=5):
        try:
            return self.packetQueue.get(True, timeout)
        except Queue.Empty:
            return None

    # The function that actually does the sniffing
    def sniffer(self, packet):
        try:
            # non-blocking: if it fails, it fails
            self.packetQueue.put(packet, False)
        except Queue.Full:
            if self.dropCount % 1000 == 0:
                sys.stderr.write("*")
                sys.stderr.flush()
            self.dropCount += 1

    def run_sniffer(self):
        sys.stderr.write("Sniffer started\n")
        rule = "src net %s or icmp" % self.dst
        sys.stderr.write("Sniffer rule \"%s\"\n" % rule);
        sniff(prn=self.sniffer,
              filter=rule,
              iface=self.iface,
              store=0)

    # Sends the message to the target in such a way
    # that the target receives the msg without
    # interference by the Great Firewall.
    #
    # ttl is a ttl which triggers the Great Firewall but is before the
    # server itself (from a previous traceroute incantation
    def evade(self, target, msg, ttl):
        source = random.randint(2000, 30000)
        sequence = random.randint(1, 31313131)
        self.send_packet(flags="S", seq=sequence, sport=source, dip=target)
        packet = self.get_packet()
        if packet:
            y = packet[TCP].seq
            sequence += 1
            self.send_packet(flags="A", seq=sequence, ack=y+1, sport=source)
        else:
            return "DEAD"

        for c in msg:
           sequence += 1
           self.send_packet(payload=c, seq=sequence, sport=source)
           self.send_packet(payload=c, seq=sequence, sport=source, ttl=ttl)

        return_message = []
        packet = self.get_packet()
        while(packet):
            return_message += packet[Raw].load
            packet = self.get_packet()
        return return_message
        
    # Returns "DEAD" if server isn't alive,
    # "LIVE" if teh server is alive,
    # "FIREWALL" if it is behind the Great Firewall
    def ping(self, target):
        # self.send_msg([triggerfetch], dst=target, syn=True)
	source = random.randint(2000, 30000)
	sequence = random.randint(1, 31313131)
        self.send_packet(flags="S", seq=sequence, sport=source, dip=target)
        
        packet = self.get_packet()
        if packet == None: return "DEAD"
        
        self.send_packet(payload = triggerfetch, flags = "A",
                         seq = sequence + 1, ack = packet[TCP].seq + 1,
                         sport = source)
        time.sleep(1)
        packet = self.get_packet()
	rst_count = 0
        while packet:
            if isRST(packet): return "FIREWALL"
            packet = self.get_packet()
        return "LIVE"

    # Format is
    # ([], [])
    # The first list is the list of IPs that have a hop
    # or none if none
    # The second list is T/F
    # if there is a RST back for that particular request
    def traceroute(self, target, hops):
        ip_list = []
        rst_list = []

        source = random.randint(2000, 30000)
        seq = random.randint(1, 31313131)
        self.send_packet(sport = source, seq = seq, flags = "S", dip=target)
        packet = self.get_packet(1)
        if packet:
            y = packet[TCP].seq
        else:
            return 'what the fuck'

	reached = False
        for i in range(1, hops):
            for _ in range(3): self.send_packet(sport = source, ack = y + 1, flags = "A", seq = seq + 1, ttl = i, payload = triggerfetch, dip=target)
            packet = self.get_packet(1)
            icmp_found = False
            rst_found = False
            while(packet):
                if not icmp_found and isTimeExceeded(packet):
                    ip_list += [packet[IP].src]
                    rst_list += [False]
                    icmp_found = True 
                if not rst_found and isRST(packet):
                    ip_list += [packet[IP].src]
                    rst_list += [True]
                    rst_found = True
                packet = self.get_packet(1)
            if not icmp_found and not rst_found:
                ip_list += ['*']
                rst_list += [False]
#            if packet and packet[IP].src == target: reached = True
        return (ip_list, rst_list)
