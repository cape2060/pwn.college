#!/usr/bin/python3

import requests
import os

from urllib.parse import quote

url = "http://challenge.localhost/"

headers = {
"Cookie":"session_user=admin"
}



response = requests.get(url,headers=headers).text

print("The Flag: "+response)
