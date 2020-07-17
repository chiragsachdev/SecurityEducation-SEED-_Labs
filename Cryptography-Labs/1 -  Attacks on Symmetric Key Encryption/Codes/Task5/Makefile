encrypt:
	openssl enc -aes-128-ecb -e -in plaintext.txt -out ciphertext_ecb.txt -k c4aP93MboJVQWZrX
	openssl enc -aes-128-cbc -e -in plaintext.txt -out ciphertext_cbc.txt -k c4aP93MboJVQWZrX
	openssl enc -aes-128-cfb -e -in plaintext.txt -out ciphertext_cfb.txt -k c4aP93MboJVQWZrX
	openssl enc -aes-128-ofb -e -in plaintext.txt -out ciphertext_ofb.txt -k c4aP93MboJVQWZrX

decrypt:
	openssl enc -aes-128-ecb -d -in ciphertext_ecb.txt -out plaintext_ecb.txt -k c4aP93MboJVQWZrX
	openssl enc -aes-128-cbc -d -in ciphertext_cbc.txt -out plaintext_cbc.txt -k c4aP93MboJVQWZrX
	openssl enc -aes-128-cfb -d -in ciphertext_cfb.txt -out plaintext_cfb.txt -k c4aP93MboJVQWZrX
	openssl enc -aes-128-ofb -d -in ciphertext_ofb.txt -out plaintext_ofb.txt -k c4aP93MboJVQWZrX

diff:
	diff -y plaintext.txt plaintext_ecb.txt > diff_ecb.txt
	diff -y plaintext.txt plaintext_cbc.txt > diff_cbc.txt
	diff -y plaintext.txt plaintext_cfb.txt > diff_cfb.txt
	diff -y plaintext.txt plaintext_ofb.txt > diff_ofb.txt
