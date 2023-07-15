#!/usr/bin/env python

# pip install websocket-client
import websocket
import json
import sys

ws = websocket.WebSocket()

ws.connect("ws://ws.qreader.htb:5789/version")

if len(sys.argv) != 2:
  msg = {"version":"0.0.2"}

msg = {"version":sys.argv[1]}

data = str(json.dumps(msg))
ws.send(data)
result = ws.recv()
print(result)
#print(json.loads(result))