#!/usr/bin/env python3
import base64, codecs, re, sys

if(len(sys.argv) != 2):
	print(f"{sys.argv[0]} <hash>")
	exit(0)

hsh = sys.argv[1].encode()

m = re.match(br'pbkdf2:sha256:(\d*)\$([^\$]*)\$(.*)', hsh)
iterations = m.group(1)
salt = m.group(2)
hashe = m.group(3)
print(f"sha256:{iterations.decode()}:{base64.b64encode(salt).decode()}:{base64.b64encode(codecs.decode(hashe,'hex')).decode()}")