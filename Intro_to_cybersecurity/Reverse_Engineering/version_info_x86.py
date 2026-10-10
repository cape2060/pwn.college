#!/usr/bin/python3

import struct
from pwn import *
print('''Dissassembly:
   0x00000000004012d7 <+147>:   call   0x40151b <read_exact>
   0x00000000004012dc <+152>:   cmp    BYTE PTR [rsp+0x2],0x63
   0x00000000004012e1 <+157>:   jne    0x4012f8 <main+180>
   0x00000000004012e3 <+159>:   cmp    BYTE PTR [rsp+0x3],0x6d
   0x00000000004012e8 <+164>:   jne    0x4012f8 <main+180>
   0x00000000004012ea <+166>:   cmp    BYTE PTR [rsp+0x4],0x36
   0x00000000004012ef <+171>:   jne    0x4012f8 <main+180>
   0x00000000004012f1 <+173>:   cmp    BYTE PTR [rsp+0x5],0x65
   0x00000000004012f6 <+178>:   je     0x40130c <main+200>
   0x00000000004012f8 <+180>:   lea    rdi,[rip+0xe17]        # 0x402116
   0x00000000004012ff <+187>:   call   0x401130 <puts@plt>
   0x0000000000401304 <+192>:   or     edi,0xffffffff
   0x0000000000401307 <+195>:   call   0x4011e0 <exit@plt>
   0x000000000040130c <+200>:   cmp    WORD PTR [rsp+0x6],0x87
   0x0000000000401313 <+207>:   lea    rdi,[rip+0xe19]        # 0x402133
   0x000000000040131a <+214>:   jne    0x4012ff <main+187>
   0x000000000040131c <+216>:   xor    eax,eax
   0x000000000040131e <+218>:   call   0x401426 <win>
''')

context.log_level = 'error'

with open('image.cimg','wb') as file:
#    payload  = b"cm6e"+struct.pack("<Q",135)
    payload = b"cm6e"+int(135).to_bytes(8,"little")
    file.write(payload)


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
