#!/usr/bin/python3

import random

while 1:
	a = random.randint(0x10000,0xfffff)
	b = random.randint(0x10000,0xfffff)
	if (a*b) & 0xffffffff <=37:
		print(hex(a),hex(b))
		break
"""
479209
>>> 0x78590
492944
"""
