from Crypto.Cipher import AES
from Crypto.Util import Padding

# defining known values and converting them from hex to binary strings
plaintext=b"This is a top secret."
iv_hex='aabbccddeeff00998877665544332211'
ciphertext_hex="764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2"
iv=bytes.fromhex(iv_hex)
ciphertext=bytes.fromhex(ciphertext_hex)
key=""

# Reading the english wordlist into a list
fp=open("words.txt","r")
wordlist_ip=fp.readlines()
fp.close()

# removing the whitespaces and \n from the words and storing the words in a new dictionary
wordlist=[]
for word in wordlist_ip:
    word=word.replace("\n","")
    word=word.strip()
    wordlist.append(word)

# applying bruteforce on the plaintext with keys from the english wordlist
for word in wordlist:
    # padding the key with pound size to make it 128 bits
    # # is 0x23 in hex 
    if len(word) <= 16:
        n=16-len(word)
        key_bin=word.encode("ascii")+b"\x23"*n
    # create instance of the object of the AES cipher
    cipher=AES.new(key_bin,AES.MODE_CBC,iv)
    # encrypt the plaintext with padding with block size set as 16 bytes
    ciphertext_new=cipher.encrypt(Padding.pad(plaintext,16))
    if ciphertext ==ciphertext_new:
        key=word
        break
print("The key is :",key)