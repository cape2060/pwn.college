#!/usr/bin/python3

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad,pad
from binascii import unhexlify

context.log_level = 'error'
print("Connecting to target...")
s = ssh(
host="dojo.pwn.college",
user="hacker",
keyfile="../../key"
)
print("Connected.")
print("Calculating iv for text \"flag!\"....")
io = s.process('/challenge/dispatcher')
ball = io.recvall()
io.close()
ct = ball.decode().split(": ")[1][:-1][32:]
iv = bytes.fromhex(ball.decode().split(": ")[1][:-1][:32])

#remainaing = ball.decode().split(": ")[1][:-1][:32][10:]

dec_text = bytes.fromhex(xor(pad(b"sleep",16),iv).hex())
need = pad(b"flag",16)

new_iv = xor(dec_text,need).hex()+ct

print("The ciphertext is: ",new_iv)
print("Trying the calculated iv.....")

io = s.process("/challenge/worker")
payload = "TASK: "+new_iv
io.sendline(payload.encode())
print(io.recvline())
io.interactive()
io.close()
