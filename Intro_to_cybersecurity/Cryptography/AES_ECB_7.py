#!/usr/bin/python3

from pwn import *


context.log_level = 'error'
io = process('/challenge/run')

def sender(data):
    io.sendline(data.encode().hex().encode())
    return io.recvline(keepends=False).decode().split(': ')[1]

payload = 'a'*64
result = 'a'*64

for i in range(59):
    cipher_block = sender(payload[:-1])[:128]
    for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}|_-+.><,":
        result = result[1:]+c
        block = sender(result)[:128]
        if cipher_block == block:
            print(result)
            break
        result = "a" + result[:-1]
    payload = payload[:-1]
print(result)
