from scapy.all import *
def print_pkt(pkt):
    pkt.show()

pkt = sniff(filter="tcp && host 10.0.2.5",prn=print_pkt)