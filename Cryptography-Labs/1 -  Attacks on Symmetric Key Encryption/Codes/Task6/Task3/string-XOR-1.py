from Crypto.Util import Padding
temp=""

plaintext=(Padding.pad("Yes",16)).encode("ascii")
pt1=plaintext.hex()
iv1="31323334353637383930313233343536"
iv2="31323334353637383930313233343537"
pt1list=bytearray.fromhex(pt1)
iv1list=bytearray.fromhex(iv1)
iv2list=bytearray.fromhex(iv2)

templist=bytearray((x^y for x,y in zip(pt1list,iv1list)))
ip2list=bytearray((x^y for x,y in zip(templist,iv2list)))

ip2 = bytes.fromhex(ip2list.hex())
print(ip2.decode())