#!/usr/bin/python3

from pwn import *
import re
context.log_level = 'error'

levels = {
        "TS":4,
        "S":3,
        "C":2,
        "UC":1
        }
def match_level(sl,ol,method):
    if method == "read":
        if levels[sl] >= levels[ol]:
            return 1
        else:
            return 0
    elif method == 'write':
        if levels[sl] <= levels[ol]:
            return 1
        else:
            return 0
    return 0
def match_catagory(sc,oc,method):
    if method == 'read':
        if oc <= sc:
            return 1
        else:
            return 0
    elif method == 'write':
        if sc <= oc:
            return 1
        else:
            return 0
    return 0

def parser(question):
    read = 0
    write = 0
    subject_level = ""
    object_level = ""
    if 'write' in question:
        write = 1
    else:
        read = 1
    sl = re.findall(r"level [A-Z]+",question)[0].split()[1]
    ol = re.findall(r"level [A-Z]+",question)[1].split()[1]
    sc = re.findall(r"{[A-Z,\s]*}",question)[0]
    oc = re.findall(r"{[A-Z,\s]*}",question)[1]
    return (write,read,sl,ol,sc,oc)

def main():
    io = process('/challenge/run')
    data = io.recvuntil(b"Q ").decode()
    #level = data.split('sensitive):\n')[1].split('5 ')[0].split('\n')[:-1]
    question = io.recvline().decode().split('1.')[1].strip()
    print(question)
    for i in range(64):
        write,read,sl,ol,sc,oc = parser(question)
        sc = set() if sc == '{}' else set(sc.strip('{}').replace(' ','').split(','))
        oc = set() if oc == '{}' else set(oc.strip('{}').replace(' ','').split(','))
        method = 'write' if write else 'read'
        if match_level(sl,ol,method) and match_catagory(sc,oc,method):
            io.sendline(b'yes')
        else:
            io.sendline(b'no')
        print(io.recvline())
        try:
            question = io.recvline().decode().split(f'Q {i+2}. ')[1].strip()
            print(question)
        except:
            continue
    io.interactive()

if __name__ == "__main__":
    main()
