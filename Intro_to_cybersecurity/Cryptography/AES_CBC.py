#!/usr/bin/python3

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from binascii import unhexlify

context.log_level = 'error'
print("Connecting to target...")
s = ssh(
host="dojo.pwn.college",
user="hacker",
keyfile="../../key"
)
print("Decrypting...")
io = s.process('/challenge/run')
ball = io.recvall()
key = unhexlify(ball.decode().split('\n')[0].split(": ")[1])
ct = unhexlify(ball.decode().split('\n')[1].split(": ")[1])

cipher = AES.new(key,mode=AES.MODE_CBC)
pt = unpad(cipher.decrypt(ct),cipher.block_size)
print("Your decrypted Flag: ",pt)
