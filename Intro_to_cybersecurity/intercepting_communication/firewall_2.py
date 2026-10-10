#!/usr/bin/python3

from pwn import *

context.log_level = 'error'

s = ssh(host="dojo.pwn.college",user="hacker",keyfile="../../key")

io = s.process('/challenge/run')

io.sendline(b'iptables -A INPUT -p tcp --dport 31337 -s 10.0.0.3 -j DROP')

io.interactive()
