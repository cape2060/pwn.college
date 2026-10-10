#!/usr/bin/python3

import requests
import os

from urllib.parse import quote

url = "http://challenge.localhost/?session_user="

payload = "admin"

full_url = url+payload

response = requests.get(full_url).text

print("The Flag: "+response)
