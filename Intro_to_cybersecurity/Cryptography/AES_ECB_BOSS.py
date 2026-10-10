import requests
import base64

def reset():
    url = "http://challenge.localhost/reset"
    requests.post(url)

def send_content(data):
    url = "http://challenge.localhost/"
    d = {
    "content":f"{data}"
    }
    res = requests.post(url,data=d)
    return base64.b64decode(res.text.split('pre>')[1][:-2]).hex()[:128]
payload = 'a'*62
flag = 'a'*63+'|'
reset()
for i in range(60):
    cipher_block = send_content(payload)
    reset()
    for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890|+={}[]-_.":
        flag = flag[1:] + c
        block = send_content(flag)
        reset()
        if cipher_block == block:
            print(flag)
            break
        flag = 'a' + flag[:-1]
    payload = payload[:-1]
print('Your Falg: ',flag[5:])
