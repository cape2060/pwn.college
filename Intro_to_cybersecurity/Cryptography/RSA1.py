#!/usr/bin/python3

from pwn import *
from Crypto.Util.number import long_to_bytes,bytes_to_long
context.log_level = 'error'

s = ssh(host="dojo.pwn.college",user="hacker",keyfile="../../key")

io = s.process('/challenge/run')

data = io.recvall().decode().split('\n')[:-1]
n = data[0].split('n = ')[1]
e = data[1].split('e = ')[1]
d = data[2].split('d = ')[1]
ct = bytes.fromhex(data[3].split(': ')[1])

print("Your Flag: "+pow(int.from_bytes(ct,'little'),int(d,16),int(n,16)).to_bytes(256,'little').decode().split('\n')[0])

