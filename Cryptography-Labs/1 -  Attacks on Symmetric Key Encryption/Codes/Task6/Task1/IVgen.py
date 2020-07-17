import random as rd
s="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
iv_lst=rd.sample(s,16)
iv=''.join(iv_lst)
print(iv)