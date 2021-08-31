#!/usr/bin/env python
import urllib
from Crypto.Cipher import DES
import base64
from pydes import des

#It's just a test.

#Java object Serialized and encode with base64
text= "wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RcVjhMDN4sZB70KtDtngjDm0mNzA9qHjYerxo0jW7zu11SwN/t3lVW5GSeZ1PEA3OZ3jFUE="
print("Original: "+text)

#Key from web.xml.bak
key = base64.b64decode("SnNGOTg3Ni0=")
 
#Obj
decipher = DES.new(key, DES.MODE_ECB)

#Padd
def ja(text):
	if len(text)%8!=0:
	    toAdd = 8 - len(text) % 8
	    text += chr(toAdd) * toAdd	    
	return text
BS = 8
def pad(text):
    return text + (BS - len(text) % BS) * chr(BS - len(text) % BS)

#Decript Java Object
print("Decript:")
print(decipher.decrypt(pad(text)))

#Encrypt
f = decipher.decrypt(pad(text))
cipher = DES.new(key, DES.MODE_ECB)
test =cipher.encrypt(f)
print("Encript: "+test[:-4])
