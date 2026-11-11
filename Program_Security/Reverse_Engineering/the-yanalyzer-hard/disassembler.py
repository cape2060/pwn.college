#!/usr/bin/python3

from Crypto.Util.number import long_to_bytes as lb


def get_vmcode():
    with open("vm_code","rb") as file:
        code = file.read()

    return code

def interprete_imm(register,data,registers):
    registers[register] = data
    print(f"{registers=}")
    print(f"MOV {hex(register)}, {hex(data)}\n")
    return registers

def interprete_add(register1,register2,registers):
    registers[register1] = (registers[register1] + registers[register2]) & 0xff
    print(f"{registers=}")
    print(f"ADD {hex(register1)}, {hex(register2)}\n")
    return registers

def interprete_stm(register1,register2,memory,registers):
    memory[registers[register1]] = registers[register2]
    print(f"STM {hex(register1)}, {hex(register2)}\n")
    return memory

def interprete_ldm(register1,reg2,memory,registers):
    registers[register1] = memory[registers[reg2]]
    print(f"{registers=}")
    print(f"LDM {hex(register1)}, {hex(reg2)}\n")
    return registers

def interprete_cmp(re1,re2,registers):
    var_406 = 0
    a = registers[re1]
    b = registers[re2]
    if a > b:
        var_406 |= 0x10
    if a < b:
        var_406 |= 0x2
    if a == b:
        var_406 |= 4
    if a != b:
        var_406 |= 0x1
    if (not a and not b):
        var_406 |= 0x8
    print(f"CMP {hex(re1)}, {hex(re2)}\n")
    return var_406

def interprete_jmp(r1,r2,var_405,var_406,registers):
    ball = ((r1) and not (var_406 & r1))
    if ball:
        print(f"JMP {hex(r1)} {hex(r2)} {var_406=} NOT TAKEN\n")
        return var_405
    
    print(f"JMP {hex(r2)} Taken\n")
    var_405 = registers[r2]
    return var_405

def interprete_sys(r1,r2):
    dictionary = {0x10: "open",0x4:"read_code",0x20:"read_memory",1:"write",8:"sleep",0x2:"exit"}
    print(f"SYSCALL {dictionary[r1]}\n")

def main(memory):
    code = get_vmcode()
    temp = code
    registers = {0x1:0,0x2:0,0x10:0,0x20:0,0x4:0,0x8:0,0x40:0}
    stack = []
    ip = 0
    var_405 = 0
    var_406 = 0
    for i in range(len(code)//3 + 120):
        data = code[ip:ip+3]
        opcode = data[1]
        reg1 = data[0]
        reg2 = data[2]
        if opcode == 0x8:
            if reg1 == 0x10:
                var_405 = reg2
            elif reg1 == 0x40:
                var_406 = reg2
            registers = interprete_imm(reg1,reg2,registers)
        elif opcode == 0x2:
            registers = interprete_add(reg1,reg2,registers)
        elif opcode == 0x40:
            memory = interprete_stm(reg1,reg2,memory,registers)
        elif opcode == 0x10:
            registers = interprete_ldm(reg1,reg2,memory,registers)
        elif opcode == 0x4:
            var_405 = interprete_jmp(reg1,reg2,var_405,var_406,registers)
        elif opcode == 0x20:
            interprete_sys(reg1,reg2)
        elif opcode == 0x1:
            if reg1 == 0:
                stack.append(registers[reg2])
                print(f"{stack=}")
                print(f"PUSH {hex(reg2)} {stack}\n")
            elif reg2 == 0:
                registers[reg1] = stack.pop()
                print(f"{stack=}")
                print(f"POP {hex(reg1)} {stack}\n")
            else:
                registers[reg1] = registers[reg1]
                print(f"{stack=}")
                print(f"PUSH {hex(reg2)}\nPOP {hex(reg1)}\n")
        else:
            var_406 = interprete_cmp(reg1,reg2,registers)
        ip = var_405 * 3
        var_405 += 1
    return memory

if __name__ == "__main__":
    memory = [0]*0x100
    memory = main(memory)
    print(memory)
    mem = [0]*0x100
    #copy the key into our input section in memory so that i can see is that the exact key 
    #if all compare happena and call to flag then key is correct
    for i in range(12):
        mem[59-i] = memory[146-i]

    mem = main(mem)
    print("Your key: ",mem[135:147])
