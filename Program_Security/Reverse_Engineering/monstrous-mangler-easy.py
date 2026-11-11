#!/usr/bin/python3

from pwn import *
from Crypto.Util.number import bytes_to_long,long_to_bytes
import sys

expected = b"\xe3\xe6FgP7D\xf0\xe8\x84g\x9c2H\xfb\xfe^p\x8a\\-\x95\x921\x1a\xf2\xa1\xd4nj\xc9\xfcT\xfe\x81,/\x84"

print(hex(bytes_to_long(expected)))

def matcher(password,key):
    return xor(password,long_to_bytes(key))

first = list(matcher(expected,0x2239))

first[4],first[9] = first[9],first[4]
second = first

third = matcher(second,0x352b93a647f49b)

fourth = [c ^ 0xd1 for c in third]

fifth = matcher(fourth,0xef117a69f2b3)

sixth = matcher(fifth,0xba36)

print("\033[38;5;80mYour license key: \033[38;5;90m"+sixth.decode('latin-1'))

def solver():
    io = process('./monstrous-mangler-easy')

    io.sendline(bytes(sixth))

    io.interactive()

if input("Do you want to automate solve(y/n)").lower() == 'y':
    solver()
else:
    sys.exit(1)
