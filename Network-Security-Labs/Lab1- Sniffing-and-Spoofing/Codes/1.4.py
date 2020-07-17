from scapy.all import *
def spoof_pkt(pkt):
    a=pkt[IP]
    dest=str(pkt[IP].dst)
    src=str(pkt[IP].src)
    a.dst=src
    a.src=dest
    b=pkt[ICMP]
    p=a/b
    send(p)

pkt = sniff(filter="icmp[icmptype] == icmp-echo",prn=spoof_pkt)