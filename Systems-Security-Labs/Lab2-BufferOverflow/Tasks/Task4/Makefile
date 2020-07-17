vuln:
	sudo rm /bin/sh
	sudo ln -s /bin/zsh /bin/sh
	sudo sysctl -w kernel.randomize_va_space=2
	gcc -g -z execstack -fno-stack-protector vuln_prog.c -o vuln_prog
	sudo chown root vuln_prog
	sudo chmod 4755	vuln_prog
