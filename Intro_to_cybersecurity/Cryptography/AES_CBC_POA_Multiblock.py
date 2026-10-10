#!/usr/bin/python3

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad,pad
from binascii import unhexlify
import sys

def worker(data):
    io = process("/challenge/worker")
    payload = "TASK: "+ data
    io.sendline(payload.encode())
    recv = io.recvline().decode()
    io.close()
    return recv

context.log_level = 'error'

io = process(['/challenge/dispatcher','flag'])
ball = io.recvall().decode().split(': ')[1][:-1]
io.close()
blocks = [ball[i:i+32] for i in range(0,len(ball),32)]
#print(blocks)
#sys.exit(0)

def single_block_attack(iv,ct):
    zeroing_iv = [0]*16
    for pad_val in range(1,17):
        padding_iv = [pad_val ^ c for c in zeroing_iv]
        for c in range(256):
            padding_iv[-pad_val] = c
            new_iv = bytes(padding_iv).hex()
            payload = new_iv + ct
            print(payload)
            if worker(payload) == "Unknown command!\n":
                print(payload)
                break
        zeroing_iv[-pad_val] = c ^ pad_val
    password = xor(bytes(zeroing_iv),bytes.fromhex(iv))
    return password

def full_attack():
    result = b""
    iv = blocks[0]
    for block in blocks[1:]:
        print(block)
        result += single_block_attack(iv,block)
        print(result)
#        break
        iv = block
full_attack()
