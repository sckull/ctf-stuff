#!/usr/bin/env python
import gnupg, sys, requests, urllib3
from html import unescape
from colorama import Fore, Back, Style, init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
pip uninstall gnupg
pip install python-gnupg
"""

if len(sys.argv) != 2:
	f = __file__.split("/")[-1]
	print(f"[*] Run:\n\tpython {f} < payload > ")
	exit(1)

init(autoreset=True)
URL = "https://ssa.htb/process"
gpg = gnupg.GPG()

# key 
batch_key_input = gpg.gen_key_input(
			name_real=f"{sys.argv[1]}",
			name_email="sckull@ssa.htb",
			key_type="RSA",
			key_length=1024,
			passphrase="sckullssa")

key = gpg.gen_key(batch_key_input)
print(Style.BRIGHT + ">>> Key Input <<<")
print(Fore.GREEN + batch_key_input)
#print(f"Fingerprint:\n{key.fingerprint}")

# message
message = "Secret Spy Agency is always watching.\n\n"

# sign message
signed_msg = gpg.sign(message, keyid=key.fingerprint, passphrase="sckullssa")
print(Style.BRIGHT + ">>> Signed Message <<<")
print(Fore.CYAN + str(signed_msg))

# encrypt and decrypt
# encrypted = str(gpg.encrypt(message, key.fingerprint, passphrase="sckullssa"))
# decrypted = str(gpg.decrypt(encrypted))
# print(f"Encrypted:\n{encrypted}")
# print(f"Encrypted:\n{decrypted}")

# public and private keys
public_key = gpg.export_keys(key.fingerprint)
print(Style.BRIGHT + ">>> Public Key <<<")
print(Fore.BLUE + public_key)

# private_key = gpg.export_keys(key.fingerprint, True, passphrase="sckullssa")
# print(f"Private Key:\n{private_key}")

# send data
print(Style.BRIGHT + ">>> Sending Public Key and Signed Message <<<")

data = { 'signed_text':signed_msg, 'public_key':public_key	}
r = requests.post(URL, data=data, verify=False)

if(r.status_code == 200):	
	print(Fore.GREEN + unescape(r.text))

