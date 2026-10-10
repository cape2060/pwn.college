#!/usr/bin/python3
from pwn import *
import string
context.log_level = 'error'
io = process('/challenge/run')
def plain(data):
    io.recvline()
    io.recvline()
    io.recvline()
    io.sendline(b"1")
    io.sendline(data.encode())
    return io.recvline(keepends=False).decode().split(": ")[1]
def cipher(length):
    io.recvline()
    io.recvline()
    io.recvline()
    io.sendline(b"2")
    io.sendline(str(length).encode())
    return io.recvline(keepends=False).decode().split(": ")[1]
flag = ""
for i in range(59):
    cipher_block = cipher(i+1)
    for i in string.printable:
        flag = i + flag
        block = plain(flag)
        if cipher_block == block:
            print(flag)
            break
        flag = flag[::-1][:-1][::-1]
io.close()    
print("\033[38;5;80mYour flag is: "+flag)
