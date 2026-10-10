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
print("Connected.")
print("Calculating iv for text \"flag!\"....")
io = s.process('/challenge/dispatcher')
ball = io.recvall()
io.close()
ct = ball.decode().split(": ")[1][:-1][32:]
iv = bytes.fromhex(ball.decode().split(": ")[1][:-1][:32])

remainaing = ball.decode().split(": ")[1][:-1][:32][10:]

dec_text = bytes.fromhex(xor(b"sleepaaaaaaaaaaa",iv).hex()[:10])
need = "flag!"
new_iv = ""
for b,n in zip(dec_text,need):
    for c in range(256):
        if b ^ c == ord(n):
            new_iv += str(hex(c))[2:]

new_iv += remainaing

print("The ciphertext is: ",new_iv+ct)
print("Trying the calculated iv.")

io = s.process("/challenge/worker")
payload = "TASK: "+new_iv+ct
io.sendline(payload.encode())
print(io.recvline())
io.interactive()
io.close()
