import random as rd
s="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
des_lst=rd.sample(s,8)
des_key=''.join(des_lst)
aes_lst=rd.sample(s,16)
aes_key=''.join(aes_lst)
print("DES Key:", des_key)
print("AES Key:", aes_key)