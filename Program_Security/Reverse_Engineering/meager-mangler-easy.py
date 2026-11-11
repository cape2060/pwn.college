#!/usr/bin/python3

from pwn import *

enc_password = list("bbdehhijjmnppsuuvxz")

enc_password[0],enc_password[0xb] = enc_password[0xb],enc_password[0]

enc_password[5],enc_password[0xd] = enc_password[0xd],enc_password[5]

password = "".join(enc_password)

io = process('./meager-mangler-easy')

io.sendline(password.encode())

io.interactive()
