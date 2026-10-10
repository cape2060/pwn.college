#!/usr/bin/python3

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad,pad
from binascii import unhexlify

def worker(data):
    io = process("/challenge/worker")
    payload = "TASK: "+ data
    io.sendline(payload.encode())
    io.recvline()
    recv = io.recvline().decode()
    io.close()
    return recv

context.log_level = 'error'

io = process(['/challenge/dispatcher','pw'])
ball = io.recvall()
io.close()

ct = ball.decode().split(": ")[1][:-1][32:]
iv = bytes.fromhex(ball.decode().split(": ")[1][:-1][:32])

zeroing_iv = [0]*16
for pad_val in range(1,17):
    padding_iv = [pad_val ^ c for c in zeroing_iv]
    for c in range(256):
        padding_iv[-pad_val] = c
        new_iv = bytes(padding_iv).hex()
        payload = new_iv + ct
        if worker(payload) == "Unknown command!\n":
            print(payload)
            break
    zeroing_iv[-pad_val] = c ^ pad_val
password = unpad(xor(bytes(zeroing_iv),iv),16)

io = process("/challenge/redeem")
io.sendline(password)
io.interactive()
io.close()
