#!/usr/bin/python3
from pwn import *

bytes = b"j\x029\x11+/_4\x08< \x16x?*Igz\x1apJ\x10wSn\x0eVODT5`,#=\t\"F\x03\x140E\x12\n\x0cqsl\x1fb^[KQ$)\x15vWN\x07Pi\x05\x17\\7hu\x1c6ma\x1eG8\x06|]\x0f3d->cfU~y.}%(R\'HY1@\x01;\x0bAC&\x00B\x18eX{\x19L!kZ\x13M2t\x1b\x04o:\x1d\x7fr\r"

enc_pas = b'IOVdBTsTPUovwIoe'

password = "".join([chr(bytes.index(c)) for c in enc_pas])

print(password)

io = process('./substitution-sorcery')

io.sendline(password.encode('latin-1'))

io.interactive()

