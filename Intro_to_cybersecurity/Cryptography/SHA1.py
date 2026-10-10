#!/usr/bin/python3


from hashlib  import sha256
import os

while True:
    d = os.urandom(16)
    hash = sha256(d).hexdigest()[:4]
    if hash == '0000':
        print("msg: "+d.hex())
        break
    #print(hash)
