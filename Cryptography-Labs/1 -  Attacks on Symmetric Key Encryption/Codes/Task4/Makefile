default: all
create:
	echo -n "12345" > five.txt
	echo -n "0123456789" > ten.txt
	echo -n "0123456789abcdef" > sixteen.txt
encrypt:
	openssl enc -aes-128-cbc -e -in five.txt -out five_ct.txt -k c4aP93MboJVQWZrX
	openssl enc -aes-128-cbc -e -in ten.txt -out ten_ct.txt -k c4aP93MboJVQWZrX
	openssl enc -aes-128-cbc -e -in sixteen.txt -out sixteen_ct.txt -k c4aP93MboJVQWZrX
decrypt:
	openssl enc -aes-128-cbc -d -in five_ct.txt -out five_pt.txt -k c4aP93MboJVQWZrX -nopad
	openssl enc -aes-128-cbc -d -in ten_ct.txt -out ten_pt.txt -k c4aP93MboJVQWZrX -nopad
	openssl enc -aes-128-cbc -d -in sixteen_ct.txt -out sixteen_pt.txt -k c4aP93MboJVQWZrX -nopad
sizeall:
	ls -ld five.txt
	ls -ld five_ct.txt
	ls -ld five_pt.txt
	ls -ld ten.txt
	ls -ld ten_ct.txt
	ls -ld ten_pt.txt
	ls -ld sixteen.txt
	ls -ld sixteen_ct.txt
	ls -ld sixteen_pt.txt

size:
	make sizeall > size.txt

all:
	make create
	make encrypt
	make decrypt
	make size
