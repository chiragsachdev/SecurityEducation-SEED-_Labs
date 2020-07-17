fp = open("ciphertext.txt","r")
s=fp.read()
fp.close()
count={}
freq={}
sum=0
for i in range(97,123):
    ch=chr(i)
    count[ch]=s.count(ch)
    sum+=count[ch]

for i in range(97,123):
    ch=chr(i)
    freq[ch]=(count[ch]/sum)*100
    print(ch+"\t:\t %.2f"%freq[ch])