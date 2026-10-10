#!/usr/bin/python3

from pwn import *
import base64
e = 0x10001
context.log_level = 'error'
need = int.from_bytes(b"flag","little")
a = b"3\xb6\xb03"
n = 0xd401cca976eadd3e20bf1dc513b655a46f9ad77d6ce096ee24ebd703dffc17f34e03595a1714fda1cfce7bc0896191917933336fda2b2b9d11d678e8d9cfdeea617c75bb64d2dc719a0178307b3d2135e94b3aab1a32b189eee0560baa8abef0795f95a3c851ac75b7b536fe64b479915a2c7b38ac9e4d47a9e3f91b0c22dbceea0a854b82e2d8b994073a4fee7802a4cf12ae056c0a6de6e8c548022896ec48f37f91e0190ab2507c09fb9c5e6305a06b57d18774e9b0484bfe01e5d6b013cee4f9323e08e498841cdf7e1f6091c372d4d9c431b3e5187aee740ff8c498965f21c4f5dc17acbf231f229bd9845aa8ec0812c938eac5e1671a5f62b62ab8f5b3
s = ssh(host="dojo.pwn.college",user="hacker",keyfile="../../key")

io = s.process(["/challenge/dispatcher",base64.b64encode(a).decode()])
data = io.recvall()
a = int.from_bytes(base64.b64decode(data.decode().split('(b64): ')[1].strip()),"little")
io.close()

io = s.process(["/challenge/dispatcher",base64.b64encode(b"\x02").decode()])
data = io.recvall()
b = int.from_bytes(base64.b64decode(data.decode().split('(b64): ')[1].strip()),"little")
io.close()

new = (a * b) % n
print("The answer: "+base64.b64encode(new.to_bytes(256,"little")).decode())
