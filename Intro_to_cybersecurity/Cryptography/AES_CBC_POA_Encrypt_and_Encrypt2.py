#!/usr/bin/python3
from Crypto.Random import get_random_bytes
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

last = get_random_bytes(16).hex()

def single_block_attack(ct):
    zeroing_iv = [0]*16
    for pad_val in range(1,17):
        padding_iv =[pad_val ^ b for b in zeroing_iv]
        for c in range(256):
            padding_iv[-pad_val] = c
            new_iv = bytes(padding_iv).hex()
            payload = new_iv + ct
#            print(payload)
            if worker(payload) == "Unknown command!\n":
#                print(payload)
                break
        zeroing_iv[-pad_val] = c ^ pad_val
    return bytes(zeroing_iv)

def full_attack():
    result = []
    last = get_random_bytes(16).hex()
    result.append(last)
    pt = pad(b"please give me the flag, kind worker process!",16).hex()
    pt_block =  [pt[i:i+32] for i in range(0,len(pt),32)][::-1]
    q = len(pt_block) + 1
    for p in pt_block:
        print(f"\033[38;5;80mEncrypted block {q}:",last)
        print(f"\033[38;5;214mEncrypting the block {q - 1}...")
        i = single_block_attack(last)
        priv_cipher_block = xor(i,bytes.fromhex(p)).hex()
        last = priv_cipher_block
        result.append(last)
        q -= 1
    print("The ciphertext is: "+''.join(result[::-1]))
full_attack()
