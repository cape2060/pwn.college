#!/usr/bin/python3

from pwn import *

context.log_level = 'error'

s = ssh(host='dojo.pwn.college',user='hacker',keyfile='../../key')

io = s.process('/challenge/run')

io.sendline(b'yes')

io.interactive()
