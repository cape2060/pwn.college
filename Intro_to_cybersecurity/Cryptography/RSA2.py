#!/usr/bin/python3

from pwn import *
from Crypto.Util.number import long_to_bytes,bytes_to_long,inverse
context.log_level = 'error'

s = ssh(host="dojo.pwn.college",user="hacker",keyfile="../../key")

io = s.process('/challenge/run')

data = io.recvall().decode().split('\n')[:-1]
e = int(data[0].split('e = ')[1],16)
p = int(data[1].split('p = ')[1],16)
q = int(data[2].split('q = ')[1],16)
ct = bytes.fromhex(data[3].split(': ')[1])

n = p * q
phi_n = (p - 1)*(q - 1)
d = inverse(e,phi_n)

print("Your Flag: "+pow(int.from_bytes(ct,'little'),d,n).to_bytes(256,'little').decode().split('\n')[0])

