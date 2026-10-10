#!/usr/bin/python3
import json
from pwn import *
from Crypto.Util.number import getPrime,inverse
from Crypto.Cipher import AES
import base64
from Crypto.Random.random import getrandbits
import hashlib
from Crypto.Util.Padding import pad,unpad
context.log_level = 'error'

def decoder(data):
    return base64.b64decode(data)
def encoder(data):
    return base64.b64encode(data)

io = process("/challenge/run")

data = io.recvuntil(b"B: ").decode().split('\n')

p = int([d for d in data if "p: " in d][0].split('p: ')[1],16)
g = 0x2
root_d = int([d for d in data if "d: " in d][0].split('d: ')[1],16)
root_certificate = [d for d in data if "root certificate (b64): " in d][0].split('(b64): ')[1]
roo_cert_sig = [d for d in data if "root certificate signature (b64): " in d][0].split('(b64): ')[1]
A = int([d for d in data if "A: " in d][0].split('A: ')[1],16)
name = [d for d in data if "name: " in d][0].split('name: ')[1]


#print(f"{p=}{g=}{d=}{root_certificate=}{roo_cert_sig=}{A=}{name=}")

def sender(data):
    io.sendline(data)


b = getrandbits(2048)
B = pow(g,b,p)
s = pow(A,b,p)

sender(hex(B).encode())
key = hashlib.sha256(s.to_bytes(256,'little')).digest()[:16]

cipher = AES.new(key=key,mode=AES.MODE_CBC,iv=b'\0'*16)

p = getPrime(512)
q = getPrime(512)
d = inverse(65537,(p - 1)*(q - 1))
n = p * q
user_certificate = {
"name":name,
"key":{
"e":65537,
"n":p*q
},
"signer":"root"}
cert = json.dumps(user_certificate).encode()
cert_sig = hashlib.sha256(cert).digest()

root_cert = json.loads(decoder(root_certificate).decode())
root_n=  root_cert.get('key').get('n')
user_signature_data = (
        name.encode().ljust(256, b"\0") +
        A.to_bytes(256, "little") +
        B.to_bytes(256, "little")
    )
hash_sig = hashlib.sha256(user_signature_data).digest()
io.sendlineafter(b"user certificate (b64): ",encoder(cipher.encrypt(pad(cert,cipher.block_size))))
#print(pad(cert,cipher.block_size))
io.sendlineafter(b": ",encoder(cipher.encrypt(pad(pow(int.from_bytes(cert_sig,'little'),root_d,root_n).to_bytes(256,'little'),16))))
io.sendline(encoder(cipher.encrypt(pad(pow(int.from_bytes(hash_sig,'little'),d,n).to_bytes(256,'little'),16))))

ciphertext = io.recvall().decode().split('secret ciphertext (b64): ')[1][:-1]
ct = decoder(ciphertext)
cipher_decrypt = AES.new(key=key,mode=AES.MODE_CBC,iv=b'\0'*16)
print("The Flag: "+unpad(cipher_decrypt.decrypt(ct),16).decode())
io.close()
