#!/usr/bin/python3

from pwn import *
import sys 

password = "zzyyxvvuuttsrppponmllllkjjihhhhggfddcbb"

first = list(password[::-1])

first[0x1e],first[0x23] = first[0x23],first[0x1e]
second = first

third = second[::-1]

third[4],third[0x16] = third[0x16],third[4]
fourth = third

fifth = fourth[::-1]

print("\033[38;5;204mYour license key: \033[38;5;70m"+"".join(fifth))

def solver():
    io = process("./monstrous-mangler-hard")

    io.sendline("".join(fifth).encode())

    io.interactive()

if input("\033[38;5;150mDo you want to automate the solve(Y/N): ").lower() == 'y':
    solver()
else:
    sys.exit(1)
