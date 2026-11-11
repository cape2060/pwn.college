#!/usr/bin/python3
from pwn import *

def get_instruction():
    with open('shellcode',"r") as file:
        data = file.read().split('\n')
    return data[:-1]

def byte_imm(reg1,reg2):
    opcode = b"\x40"
    arg1 = int(reg1,16).to_bytes(1,"little")
    arg2 = int(reg2,16).to_bytes(1,"little")
    return opcode+arg1+arg2

def byte_add(reg1,reg2):
    opcode = b"\x80"
    arg1 = int(reg1,16).to_bytes(1,"little")
    arg2 = int(reg2,16).to_bytes(1,"little")
    return opcode+arg1+arg2

def byte_stm(reg1,reg2):
    opcode = b"\x10"
    arg1 = int(reg1,16).to_bytes(1,"little")
    arg2 = int(reg2,16).to_bytes(1,"little")
    return opcode+arg1+arg2

def byte_ldm(reg1,reg2):
    opcode = b"\x02"
    arg1 = int(reg1,16).to_bytes(1,"little")
    arg2 = int(reg2,16).to_bytes(1,"little")
    return opcode+arg1+arg2

def byte_cmp(reg1,reg2):
    opcode = b"\x01"
    arg1 = int(reg1,16).to_bytes(1,"little")
    arg2 = int(reg2,16).to_bytes(1,"little")
    return opcode+arg1+arg2

def byte_jmp(reg1,reg2):
    opcode = b"\x08"
    arg1 = int(reg1,16).to_bytes(1,"little")
    arg2 = int(reg2,16).to_bytes(1,"little")
    return opcode+arg1+arg2

def byte_sys(reg1,reg2):
    opcode = b"\x04"
    arg1 = int(reg1,16).to_bytes(1,"little")
    arg2 = int(reg2,16).to_bytes(1,"little")
    return opcode+arg1+arg2

def byte_stk(reg1,reg2):
    opcode = b"\x20"
    arg1 = int(reg1,16).to_bytes(1,"little")
    arg2 = int(reg2,16).to_bytes(1,"little")
    return opcode+arg1+arg2

def main():
    shellcode = b""
    i = get_instruction()
    for j in i:
        o,r1,r2 = j.split()
        if o.lower() == "imm":
            shellcode += byte_imm(r1,r2)
        elif o.lower() == "add":
            shellcode += byte_add(r1,r2)
        elif o.lower() == "cmp":
            shellcode += byte_cmp(r1,r2)
        elif o.lower() == "stm":
            shellcode += byte_stm(r1,r2)
        elif o.lower() == "ldm":
            shellcode += byte_ldm(r1,r2)
        elif o.lower() == "stk":
            shellcode += byte_stk(r1,r2)
        elif o.lower() == "sys":
            shellcode += byte_sys(r1,r2)
        elif o.lower() == "jmp":
            shellcode += byte_jmp(r1,r2)
        else:
            continue
    return shellcode

if __name__ == "__main__":
    shellcode = main()

    io = process("./yancraft-hard")
    io.send(shellcode)

    io.interactive()
