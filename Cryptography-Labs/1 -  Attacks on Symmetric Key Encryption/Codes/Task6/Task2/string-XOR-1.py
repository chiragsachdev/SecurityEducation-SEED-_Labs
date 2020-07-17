temp=""
plaintext=b"This is a known message!"
pt1=plaintext.hex()
ct1="a469b1c502c1cab966965e50425438e1bb1b5f9037a4c159"
pt1list=bytearray.fromhex(pt1)
ct1list=bytearray.fromhex(ct1)

templist=bytearray((x^y for x,y in zip(pt1list,ct1list)))
# print(templist.hex())

ct2="bf73bcd3509299d566c35b5d450337e1bb175f903fafc159"
ct2list=bytearray.fromhex(ct2)

pt2list=bytearray((x^y for x,y in zip(templist,ct2list)))
pt2=bytes.fromhex(pt2list.hex())
print(pt2.decode())