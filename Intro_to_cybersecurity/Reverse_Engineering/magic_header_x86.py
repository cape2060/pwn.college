#!/usr/bin/python3
from pwn import *

print("""Disassembly: 
0x00000000004015de <+222>:   cmp    al,0x5b
   0x00000000004015e0 <+224>:   jne    0x4015fa <main+250>
   0x00000000004015e2 <+226>:   movzx  eax,BYTE PTR [rbp-0x1b]
   0x00000000004015e6 <+230>:   cmp    al,0x4f
   0x00000000004015e8 <+232>:   jne    0x4015fa <main+250>
   0x00000000004015ea <+234>:   movzx  eax,BYTE PTR [rbp-0x1a]
   0x00000000004015ee <+238>:   cmp    al,0x4e
   0x00000000004015f0 <+240>:   jne    0x4015fa <main+250>
   0x00000000004015f2 <+242>:   movzx  eax,BYTE PTR [rbp-0x19]
   0x00000000004015f6 <+246>:   cmp    al,0x72
   0x00000000004015f8 <+248>:   je     0x401610 <main+272>
   0x00000000004015fa <+250>:   lea    rdi,[rip+0xb34]        # 0x402135
   0x0000000000401601 <+257>:   call   0x401140 <puts@plt>
   0x0000000000401606 <+262>:   mov    edi,0xffffffff
   0x000000000040160b <+267>:   call   0x401210 <exit@plt>
   0x0000000000401610 <+272>:   cmp    DWORD PTR [rbp-0x20],0x0
   0x0000000000401614 <+276>:   je     0x401620 <main+288>
   0x0000000000401616 <+278>:   mov    eax,0x0
   0x000000000040161b <+283>:   call   0x401316 <win>
   0x0000000000401620 <+288>:   mov    eax,0x0
""")
context.log_level = 'error'

with open('image.cimg','wb') as file:
    file.write(b"[ONr")


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
