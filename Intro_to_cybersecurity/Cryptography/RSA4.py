#!/usr/bin/python3
import base64
from Crypto.Util.number import getPrime,inverse
from pwn import *

context.log_level = 'error'
p = getPrime(512)
q = getPrime(512)

n = p*q
e = 65537
phi = (p-1)*(q-1)
d = inverse(e,phi)
io = process("/challenge/run")
io.sendline(hex(e).encode())
io.sendline(hex(n).encode())

chal = int(io.recvuntil(b"response:").decode().split('0x')[1][:-9],16)

io.sendline(hex(pow(chal,d,n)).encode())
ct = base64.b64decode(io.recvline(keepends=False).decode().split('secret ciphertext (b64): ')[1])
#print(ct)
pt = pow(int.from_bytes(ct,'little'),d,n).to_bytes(256,'little').decode()
print(pt)
io.interactive()
