#!/usr/bin/python3

from pwn import *
import struct
import subprocess
import sys
import os
import time

"""pwn.college{oto8fo_GwsxNH45sLxAVLE7X4nc.0FOxMDMxwSM4ETN3EzW}"""
with open("/challenge/flag.cimg","rb") as file:
    data = file.read()

data = data.replace(b"\x07\x00\x93\x30\x0b\x00",b"\x07\x00\x00\x00\x00\x00")

with open("uff.cimg","wb") as file:
    file.write(data)
print("Run the ./cimg with this image and the binary itself build the flag in ascii art format")
print("Small catch : here the screen clearing is done so at last when all the flag is formed then if the whole flag does not fit in screen\n\tthen it will also be cleard so so minimize terminal screen such that whole flag can fit in the screen")
