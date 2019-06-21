#!/usr/bin/env python
import socket
import os
import requests
import time
import re
import sys
import urllib.error
from urllib.parse import urljoin
from urllib import parse
from urllib.request import urlopen, Request
from threading import Thread
from queue import Queue
from blessings import Terminal

t = Terminal()

print (t.bold_bright_yellow("""

                		 /$$$$$$$   /$$$$$$                                      /$$$$$$$$                                                                           /$$      
                		| $$__  $$ /$$__  $$                                    | $$_____/                                                                          | $$      
                		| $$  \ $$|__/  \ $$  /$$$$$$$  /$$$$$$  /$$$$$$$       | $$     /$$$$$$  /$$$$$$  /$$$$$$/$$$$   /$$$$$$  /$$  /$$  /$$  /$$$$$$   /$$$$$$ | $$   /$$
                		| $$$$$$$/   /$$$$$/ /$$_____/ /$$__  $$| $$__  $$      | $$$$$ /$$__  $$|____  $$| $$_  $$_  $$ /$$__  $$| $$ | $$ | $$ /$$__  $$ /$$__  $$| $$  /$$/
                		| $$__  $$  |___  $$| $$      | $$  \ $$| $$  \ $$      | $$__/| $$  \__/ /$$$$$$$| $$ \ $$ \ $$| $$$$$$$$| $$ | $$ | $$| $$  \ $$| $$  \__/| $$$$$$/ 
                		| $$  \ $$ /$$  \ $$| $$      | $$  | $$| $$  | $$      | $$   | $$      /$$__  $$| $$ | $$ | $$| $$_____/| $$ | $$ | $$| $$  | $$| $$      | $$_  $$ 
                		| $$  | $$|  $$$$$$/|  $$$$$$$|  $$$$$$/| $$  | $$      | $$   | $$     |  $$$$$$$| $$ | $$ | $$|  $$$$$$$|  $$$$$/$$$$/|  $$$$$$/| $$      | $$ \  $$
                		|__/  |__/ \______/  \_______/ \______/ |__/  |__/      |__/   |__/      \_______/|__/ |__/ |__/ \_______/ \_____/\___/  \______/ |__/      |__/  \__/
                                                                                                                                              
"""))
print (t.bold_bright_cyan("[#] Created By   : ES"))
print (t.bold_bright_cyan("[#] Tool Support : R3con in Depth"))
print (t.bold_bright_cyan("[#] Version      : 1.0")) 
print("\n")
hostname = input("[+] Enter the website you need to scan:~# ")

os.system("clear")

#Printing target website
print (t.bold_bright_green("""
====================================================================================
#                                  TARGET WEBSITE INFO                             #
====================================================================================
	"""))
print (t.bold_bright_cyan("[+] Target Website: ") + ("https://" + hostname))


#IP Finding
print (t.bold_bright_green("""
====================================================================================
#                                  IP ADDRESS INFO                                 #
====================================================================================
"""))
try:
	IP = socket.gethostbyname(hostname)
	print (t.bold_bright_cyan("[+] IP Address of that Website: "),IP)

except Exception as e:
	print(e)

#Whois Info
print (t.bold_bright_green("""
====================================================================================
#                                    Whois INFO                                    #
====================================================================================
"""))
try:
	print (t.bold_bright_cyan("[*] Usage: whois [IP]"))
	print("\n")
	cwd = os.getcwd()
	os.system("whois " + IP  + " > " + cwd + "/output/whois.txt")
	os.system("cat " + cwd + "/output/whois.txt | grep 'NetRange\|CIDR\|inetnum\|route\|Organization\|org\|netname\|source\|OrgTechPhone\|phone\|OrgTechEmail\|e-mail\|Comment\|remarks'")

except Exception as e:
	print(e)


#Fingerprinting Server Version Scan
print (t.bold_bright_green("""
====================================================================================
#                           FINGERPRINTING SERVER VERSION INFO                     #
====================================================================================
"""))
try:
	print (t.bold_bright_cyan("[*] Usage: wad -u [Domain]"))
	cwd = os.getcwd()
	whatweb = os.system("wad -u" + "https://" + hostname + " > " + cwd + "/output/wad.txt")
	print("\n")
	os.system("cat " + cwd + "/output/wad.txt | grep 'app\|ver' ")
	
except Exception as e:
	print(e)


#Secure Response Headers Missing Scan
print (t.bold_bright_green("""
====================================================================================
#                                  RESPONSE HEADERS INFO                           #
====================================================================================
"""))
print (t.bold_bright_cyan("[*] Usage: https://securityheaders.com/?q=[Domain]&followRedirects=on"))
print("\n")
try:
	r = requests.get("http://" + hostname)
	headers = r.headers 

	if 'Server' in headers:
		print (t.bold_bright_cyan("[+] Server                           :  ") + r.headers['Server'])

	if 'X-Powered-By' in headers:
		print (t.bold_bright_cyan("[+] Backend Technology               :  ") + r.headers['X-Powered-By'])

	if 'Strict-Transport-Security' in headers:
		print (t.bold_bright_cyan("[+] Strict-Transport-Security        :  ") + r.headers['Strict-Transport-Security'])

	if 'Expect-CT' in headers:
		print (t.bold_bright_cyan("[+] Expect-CT                        :  ") + r.headers['Expect-CT'])

	if 'Public-Key-Pins' in headers:
  		print (t.bold_bright_cyan("[+] Public-Key-Pins                  :  ") + r.headers['Public-Key-Pins'])
	 
	if 'X-Frame-Options' in headers:
		print (t.bold_bright_cyan("[+] X-Frame-Options                  :  ") + r.headers['X-Frame-Options'])

	if 'X-XSS-Protection' in headers:
		print (t.bold_bright_cyan("[+] X-XSS-Protection                 :  ") + r.headers['X-XSS-Protection'])

	if 'Cache-Control' in headers:
		print (t.bold_bright_cyan("[+] Cache-Control                    :  ") + r.headers['Cache-Control'])

	if 'Pragma' in headers:
  		print (t.bold_bright_cyan("[+] Pragma                           :  ") + r.headers['Pragma'])

	if 'Access-Control-Allow-Origin' in headers: 
		print (t.bold_bright_cyan("[+] Access-Control-Allow-Origin      :  ") + r.headers['Access-Control-Allow-Origin'])

	if 'Access-Control-Allow-Credentials' in headers:
		print (t.bold_bright_cyan("[+] Access-Control-Allow-Credentials :  ") + r.headers['Access-Control-Allow-Credentials'])  

	if 'Access-Control-Allow-Methods' in headers:
		print (t.bold_bright_cyan("[+] Access-Control-Allow-Methods     :  ") + r.headers['Access-Control-Allow-Methods'])

	if 'Content-Security-Policy' in headers:
		print (t.bold_bright_cyan("[+] Content-Security-Policy          :  ") + r.headers['Content-Security-Policy'])

	if 'Last-Modified' in headers:
		print (t.bold_bright_cyan("[+] Last-Modified                    :  ") + r.headers['Last-Modified'])

	if 'Allow' in headers:
		print (t.bold_bright_cyan("[+] Allow                            :  ") + r.headers['Allow'])

	if 'Set-Cookie' in headers:
		print (t.bold_bright_cyan("[+] Set-Cookie                       :  ") + r.headers['Set-Cookie'])

except Exception as e:
	print(e)

#Weak Cipher Scan
print (t.bold_bright_green("""
====================================================================================
#                                     Weak Cipher Scan                             #
====================================================================================
"""))
try:
	print (t.bold_bright_cyan("[*] Usage: sslscan --no-fallback [Domain]"))
	print("\n")
	os.system("sslscan --no-fallback " + hostname )
	
except Exception as e:
	print(e)

#Nmap TCP
print (t.bold_bright_green("""
====================================================================================
#                                    Nmap TCP                                      #
====================================================================================
"""))
print (t.bold_bright_cyan("[*] Usage: nmap -Pn -sV -sC -T4 -F --version-intensity 0 [IP]"))
print("\n")
try:
	os.system("nmap -Pn -sV -sC -T4 -F --version-intensity 0 " + IP)

except Exception as e:
	print(e)

#Nmap UDP
print (t.bold_bright_green("""
====================================================================================
#                                    Nmap UDP                                      #
====================================================================================
"""))
print (t.bold_bright_cyan("[*] Usage: nmap -Pn -sV -sU -sC -T4 -F --version-intensity 0 [IP]"))
print("\n")
try:
	os.system("nmap -Pn -sU -sV -sC -T4 -F --version-intensity 0 " + IP)

except Exception as e:
	print(e) 


#Robots.txt
print (t.bold_bright_green("""
====================================================================================
#                                    ROBOTS_TXT INFO                               #
====================================================================================
"""))
time.sleep(5)
concurrent = 10

def robot():
	while True:
		final_url = "https://" + hostname + q.get()
		response = requests.get(final_url)
		robot1(response.status_code,final_url)
		q.task_done()
			

def robot1(status,url):
	global t
	
	if status == 200:
		time.sleep(1)
		print (t.bold_bright_green("[+]Status_Code [" + str(status) + "] "  + "  : "), url)
	else:
		time.sleep(1)
		print (t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : "), url)


q = Queue(concurrent * 2)

for i in range(concurrent):
	th = Thread(target=robot)
	th.daemon = True
	th.start()

try:
	print (t.bold_bright_cyan("[*] Usage: https://hostname/robots.txt"))
	print("\n")
	url = "http://" + hostname + "/robots.txt"

	response = urlopen(Request(url, headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'}))

	if response.code == 200:
		read = response.read()
		with open(cwd + "/output/robot1.txt", "wb") as f:
			f.write(read)
			f.close()
		os.system("cat " + cwd + "/output/robot1.txt " + " | grep -i 'allow' " + " | awk '{print $2}' " + " > " + cwd + "/output/robot2.txt")
		with open(cwd + "/output/robot2.txt", "r") as f:
			url	= f.read().split()
			f.close()
		for i in url:
			q.put(i.strip())
		q.join()

except urllib.error.HTTPError as e:
	print (t.bold_bright_red("Robots.txt is Not Configured[" + str(e.code) + "]" + ": "),url)


#Sub-Domain Finding
print (t.bold_bright_green("""
====================================================================================
#                                Sub-Domain                                        #
====================================================================================
"""))
time.sleep(5)
concurrent = 10

def doWork():
	while True:
		try:
			netloc = q.get()
			url = "https://" + netloc
			status, url = getStatus(url)
			doSomethingWithResult(status, url)
			q.task_done()
		except requests.exceptions.ConnectionError as e:
			q.task_done()
			pass


def getStatus(ourl):
   try:
       headers = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0" }
       res = requests.get(ourl, headers= headers)
       return res.status_code, ourl
   except:
       return "No Response Code", ourl

def doSomethingWithResult(status, url):
	global cname
	if status == 200:
		time.sleep(1)
		print (t.bold_bright_yellow("[+]Status_Code [" + str(status) + "] "  + "  : "), url)
	elif status == 401:
		time.sleep(1)
		print (t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : "), url)
	elif status == 403:
		time.sleep(1)
		print (t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : "), url)
	elif status == 404:
		time.sleep(1)
		print (t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : "), url)
	elif status == 429:
		time.sleep(1)
		print (t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : "), url)
	elif status == 500:
		time.sleep(1)
		print (t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : "), url)
	elif status == 504:
		time.sleep(1)
		print (t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : "), url)
	elif status == 522:
		time.sleep(1)
		print (t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : "), url)
	elif status == 530:
		time.sleep(1)
		print (t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : "), url)
	else:
		time.sleep(1)
		print (t.bold_bright_red("[-]" + str(status) + "    : "), url)
    
q = Queue(concurrent * 2)

for i in range(concurrent):
	th1 = Thread(target=doWork)
	th1.daemon = True
	th1.start()

url = 'https://www.virustotal.com/vtapi/v2/domain/report'
params = {'apikey': '83f01852d8f7dbd65b2a2a31e43f2b79a4f91ac7f14f85ab9e1fb9392c51c3ea', 'domain': hostname }
response = requests.get(url, params=params)
data = response.json()
try:
  sub1 = data["subdomains"]
except:
  sub1 = []
try:
 sub2 = data["domain_siblings"]
except:
 sub2 = []

subdomains = sub1 + sub2

t = Terminal()

try:
	for url in subdomains:
		q.put(url.strip())
	q.join()
except:
	pass

#Critical-File Finding
print (t.bold_bright_green("""
====================================================================================
#                                Critical-File Found                              #
====================================================================================
"""))
time.sleep(5)
concurrent = 10
print (t.bold_bright_cyan("[*] Usage: https://hostname/[Wordlist]"))
print("\n")
def critical_file_found():
	while True:
		try:
			word = q.get()
			test_url = target_url + "/" + word
			headers = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0" }
			response = requests.get(test_url,headers)
			code(response.status_code,test_url)
			q.task_done()
		except requests.exceptions.ConnectionError as e:
			q.task_done()
			pass


def code(status,url):
	try:
		if status == 200:
			time.sleep(1)
			print (t.bold_bright_yellow("[+]Status_Code [" + str(status) + "] "  + "  : "), url)
		elif status == 401:
			time.sleep(1)
			print (t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : "), url)
		elif status == 403:
			time.sleep(1)
			print (t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : "), url)
		else:
			pass

	except Exception as e:
		print(e)

q = Queue(concurrent * 2)

for i in range(concurrent):
	th2 = Thread(target=critical_file_found)
	th2.daemon = True
	th2.start()

target_url = "https://" + hostname

try:
	file = []
	with open(cwd + "/input/wordlist.txt","r") as wordlist_file:
		for line in wordlist_file:
			file.append(line.strip())
	wordlist_file.close()
	for line in file:
		q.put(line)
	q.join()
			
except Exception as e:
	print(e)


#Open-Redirection
print (t.bold_bright_green("""
====================================================================================
#                                   Open-Redirection                              #
====================================================================================
"""))
time.sleep(5)
concurrent = 10
print (t.bold_bright_cyan("[*] Usage: https://hostname/[Payloadlist]"))
print("\n")
def open_redirection():
	while True:
		try:
			word = q.get()
			test_url = target_url  + word
			headers = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0" }
			response = requests.get(test_url,headers)
			res_code(response.status_code,test_url)
			q.task_done()
		except requests.exceptions.ConnectionError as e:
			q.task_done()
			pass


def res_code(status,url):
	try:
		if status == 200:
			time.sleep(1)
			print (t.bold_bright_yellow("[+]Status_Code [" + str(status) + "] "  + "  : "), url)
		else:
			time.sleep(1)
			print (t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : "), url)

	except Exception as e:
		print(e)

q = Queue(concurrent * 2)

for i in range(concurrent):
	th2 = Thread(target=open_redirection)
	th2.daemon = True
	th2.start()

target_url = "https://" + hostname

try:
	file = []
	with open(cwd + "/input/open_redirection.txt","r") as wordlist_file:
		for line in wordlist_file:
			file.append(line.strip())
	wordlist_file.close()
	for line in file:
		q.put(line)
	q.join()
			
except Exception as e:
	print(e)

#Web Crawler
print (t.bold_bright_green("""
====================================================================================
#                                     Web Crawler                                  #
====================================================================================
"""))
target_url = "https://" + hostname
target_links = []

def extract_links_from(url):
	response = requests.get(url)
	content = response.content
	return re.findall('(?:href=")(.*?)"',str(content))

def crawl(url):
	href_links = extract_links_from(url)
	for link in href_links:
		link = urljoin(url, link)

		if "#" in link:
			link = link.split("#")[0]

		if target_url in link and link not in target_links:
			target_links.append(link)
			print(t.bold_bright_green("[+]URL Found: "),link)
			crawl(link)

crawl(target_url)






