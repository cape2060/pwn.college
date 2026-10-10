#!/usr/bin/python3
from pwn import *
import string
context.log_level = 'error'
io = process('/challenge/run')
def plain(data):
    io.recvuntil(b"Choice")
    io.sendline(b"1")
    io.sendline(data.encode())
    return io.recvuntil(b'Choose').decode().split(': ')[1].split('\n')[0]
def cipher(length):
    io.recvuntil(b"Choice")
    io.sendline(b"2")
    io.sendline(str(length).encode())
    return io.recvuntil(b'Choose').decode().split(': ')[1].split('\n')[0]
def breaker(result):
    return [result[i:i+32] for i in range(0,len(result),32)]
payload = 'a'*64
result = 'a'*64
for i in range(59):
    res = cipher(payload[:-1])[:128]
    for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}|_-+.><,":
        result = result[1:]+c
#        print(plain(result),res,c)
        if plain(result) == res:
            print(result)
            break
        result = 'a' + result[:-1]
    payload = payload[:-1]
print(result[5:])
