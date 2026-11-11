#!/usr/bin/python3

from pwn import *

enc = b"l\x84d\x91g\x9ap\x95y\x87p\x8fn\x8eq\x84e\x91~"

first = enc[::-1]

second = [c ^ 9 if i % 2==0 else c ^ 0xfe for i,c in enumerate(first)]

second[1],second[0xf] = second[0xf],second[1]

third = bytes(second)

io = process('./meager-mangler-hard')

io.sendline(third)

io.interactive()


