#!/usr/bin/python3

import subprocess
import os
print('when you run /challenge/run it change the owner from root to hacker with permision 000 in /flag file')
subprocess.Popen(['chmod','+r','/flag'])
os.system('cat /flag')

