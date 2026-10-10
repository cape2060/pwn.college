#!/usr/bin/python3


from hashlib  import sha256
import os
import base64


data = base64.b64decode('KkKKptbF1I6C2NwO7m2ZS1dYplwTgguRT6PCXwQLyRg=')

while True:
    d = os.urandom(16)
    a = d
    d = data + d
    hash = sha256(d).hexdigest()[:4]
    if hash == '0000':
        print("msg: "+base64.b64encode(a).decode())
        break
    #print(hash)
