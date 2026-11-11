#!/usr/bin/python3
from pwn import *
"""
imm=128         stm=2           add=32          sys=1           stk=16
write=64        open=4          read=128
unknown_reg=32  reg_400=4       reg_401=2       reg_402=64      reg_405=8 
"""

def get_instruction():
    with open('shellcode',"r") as file:
        data = file.read().split('\n')
    return data[:-1]

def byte_imm(imm,d,reg1,reg2):
    opcode = imm.to_bytes(1,"little")
    reg1 = d[reg1]
    arg1 = reg1.to_bytes(1,"little")
    arg2 = int(reg2,16).to_bytes(1,"little")
    return arg2+opcode+arg1

def byte_add(add,d,reg1,reg2):
    opcode = add.to_bytes(1,"little")
    reg1 = d[reg1]
    reg2 = d[reg2]
    arg1 = reg1.to_bytes(1,"little")
    arg2 = reg2.to_bytes(1,"little")
    return arg2+opcode+arg1

def byte_stm(stm,d,reg1,reg2):
    opcode = stm.to_bytes(1,"little")
    reg1 = d[reg1]
    reg2 = d[reg2]
    arg1 = reg1.to_bytes(1,"little")
    arg2 = reg2.to_bytes(1,"little")
    return arg2+opcode+arg1

def byte_ldm(reg1,reg2):
    opcode = b"\x02"
    reg1 = d[reg1]
    reg2 = d[reg2]
    arg1 = reg1.to_bytes(1,"little")
    arg2 = reg2.to_bytes(1,"little")
    return arg2+opcode+arg1

def byte_cmp(reg1,reg2):
    opcode = b"\x01"
    reg1 = d[reg1]
    reg2 = d[reg2]
    arg1 = reg1.to_bytes(1,"little")
    arg2 = reg2.to_bytes(1,"little")
    return arg2+opcode+arg1

def byte_jmp(reg1,reg2):
    opcode = b"\x08"
    reg1 = d[reg1]
    reg2 = d[reg2]
    arg1 = reg1.to_bytes(1,"little")
    arg2 = reg2.to_bytes(1,"little")
    return arg2+opcode+arg1

def byte_sys(sys,d,reg1,reg2):
    opcode = sys.to_bytes(1,"little")
    reg1 = d[reg1]
    reg2 = d[reg2]
    arg1 = reg1.to_bytes(1,"little")
    arg2 = reg2.to_bytes(1,"little")
    return arg2+opcode+arg1

def byte_stk(reg1,reg2):
    opcode = b"\x10"
    reg1 = d[reg1]
    reg2 = d[reg2]
    arg1 = reg1.to_bytes(1,"little")
    arg2 = reg2.to_bytes(1,"little")
    return arg2+opcode+arg1

def main(*args):
    d = {"r1":args[0],"r2":args[1],"r3":args[2],"open":args[3],"read":args[4],"write":args[5],"exit":args[6]}
    shellcode = b""
    i = get_instruction()
    for j in i:
        o,r1,r2 = j.split()
        if o.lower() == "imm":
            shellcode += byte_imm(args[7],d,r1,r2)
        elif o.lower() == "add":
            shellcode += byte_add(args[8],d,r1,r2)
        elif o.lower() == "cmp":
            shellcode += byte_cmp(r1,r2)
        elif o.lower() == "stm":
            shellcode += byte_stm(args[9],d,r1,r2)
        elif o.lower() == "ldm":
            shellcode += byte_ldm(r1,r2)
        elif o.lower() == "stk":
            shellcode += byte_stk(r1,r2)
        elif o.lower() == "sys":
            shellcode += byte_sys(args[10],d,r1,r2)
        elif o.lower() == "jmp":
            shellcode += byte_jmp(r1,r2)
        else:
            continue
    return shellcode

