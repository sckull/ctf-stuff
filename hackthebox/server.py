#!/usr/bin/env python

import sys
import logging
import json

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

from http.server import BaseHTTPRequestHandler, HTTPServer

class BaseServer(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def redirect(self):
        self.send_response(307)
        self.send_header('Location',"http://127.0.0.1--REDACTED--")
        self.end_headers()


    def do_GET(self):
        #self._set_headers()
        self.redirect()

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        self._set_headers()
        #logging.info(f"{bcolors.OKGREEN}POST {bcolors.ENDC} request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",str(self.path), str(self.headers), post_data.decode('utf-8'))
        #body = json.loads(post_data.decode('utf-8'))
        #print(body['body'])
        # if not json
        print(f'{bcolors.OKGREEN} {post_data} {bcolors.ENDC}')

def run(server_class=HTTPServer, handler_class=BaseServer, port=80):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print('HTTP server running on port %s'% port)
    httpd.serve_forever()

if __name__ == "__main__":
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
