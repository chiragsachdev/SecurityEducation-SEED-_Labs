from scapy.all import *
for i in range(1,65):
    a=IP()
    a.dst="128.230.18.198"
    a.ttl=i
    b=ICMP()
    p=a/b
    send(p)
    for j in range(10000000):
#       time delay loop