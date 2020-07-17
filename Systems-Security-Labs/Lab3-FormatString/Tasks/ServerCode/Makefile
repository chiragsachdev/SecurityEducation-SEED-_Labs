all:
	sudo sysctl -w kernel.randomize_va_space=0
	gcc -g -z execstack -o server server.c
	sudo ./server
