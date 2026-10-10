#!/usr/bin/python3

from pwn import *

context.log_level = 'error'

s = ssh(host="dojo.pwn.college",user="hacker",keyfile="../../key")

io = s.process('/challenge/run')
print("Added the ip 10.0.0.3")
io.sendline(b'ip addr add 10.0.0.3/24 dev eth0')
print('Enable the interface')
io.sendline(b'ip link set eth0 up')
print("Listening in port 31337")
io.sendline(b'nc -nvlp 31337')

io.interactive()
