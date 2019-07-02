#!/usr/bin/env python
import socket
import os
import requests
import time
import re
import sys
import optparse
import dns.resolver
import urllib.error
from urllib.parse import urljoin
from urllib import parse
from urllib.request import urlopen, Request
from threading import Thread
from queue import Queue
from blessings import Terminal

parser = optparse.OptionParser()
parser.add_option("-d","--domain", dest="hostname", help="Give the domain you want scan without 'https://'")
parser.add_option("-t","--nmap_tcp", dest="nmap_tcp", help="Nmap TCP Scan type options from [1-4]             1.Fast scan[Top 100 port scan]                      2.Fast scan with service,os & version detection         3.Intense scan with service,os & version detection     4.All port scan with service,os & version detection")
parser.add_option("-u","--nmap_udp", dest="nmap_udp", help="Nmap UDP Scan type options from [1-4]             1.Fast scan[Top 100 port scan]                      2.Fast scan with service,os & version detection         3.Intense scan with service,os & version detection        4.All port scan with service,os & version detection")

(options, arguments) = parser.parse_args()

hostname = options.hostname
nmap_tcp = options.nmap_tcp
nmap_udp = options.nmap_udp

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
print (t.bold_bright_cyan("[#] Created By   : Mr.Robot"))
print (t.bold_bright_cyan("[#] Tool Support : R3con in Depth and Fully Automated"))
print (t.bold_bright_cyan("[#] Version      : 1.2")) 

print("\n")
print (t.bold_bright_red("[#]Hold on Apache Server is starting.....!"))
os.system("service apache2 start")
os.system("mkdir /var/www/html/output")
os.system("mkdir /var/www/html/output/wad")
os.system("mkdir /var/www/html/output/nmap")
os.system("clear")

#Scan Information

def scan_info(module,target_host):
    modules = ('Whois','SSLScan','dns_enum','Nmap_TCP','Nmap_UDP','Robots.txt')
    f = open('/var/www/html/output/'+modules[module]+'.html', 'w')
    f.write("<h3>"+modules[module]+ " Scan Result: "+hostname+"</h3>")
    f.close()

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
    os.system("whois " + IP  + " > " + "/var/www/html/output/whois.txt")
    os.system("cat /var/www/html/output/whois.txt | grep 'NetRange\|CIDR\|inetnum\|route\|Organization\|org\|netname\|source\|OrgTechPhone\|phone\|OrgTechEmail\|e-mail\|Comment\|remarks' " + " > " + "/var/www/html/output/whois1.txt")
    os.system("cat /var/www/html/output/whois1.txt")
    scan_info(0,hostname)
    os.system("cat /var/www/html/output/whois1.txt |aha --word-wrap >> /var/www/html/output/Whois.html")
    print("\n")
    change = cwd + "/input/webscreenshot.py"
    os.system("python " + change + " 127.0.0.1/output/Whois.html" + " -o " + cwd + "/output/screenshot/"+hostname)

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
	socket.setdefaulttimeout(60 * 60)
	os.system("wad -u" + "http://" + hostname + " > " + "/var/www/html/output/wad/wad.txt")
	print("\n")
	os.system("""cat /var/www/html/output/wad/wad.txt | egrep '"app":|"ver":'  >  /var/www/html/output/wad/wad1.txt""")
	os.system("cat /var/www/html/output/wad/wad1.txt")
	print("\n")
	change = cwd + "/input/webscreenshot.py"
	os.system("python " + change + " 127.0.0.1/output/wad/wad.txt" + " -o " + cwd + "/output/screenshot/"+hostname)
	
except Exception as e:
	print(e)

#Exploit Search
print (t.bold_bright_green("""
====================================================================================
#                                     Exploit Search                               #
====================================================================================
"""))
print (t.bold_bright_cyan("[*] Usage: searchsploit [(Application) (version)]"))
os.system("""sed 's/ //g' /var/www/html/output/wad/wad1.txt > /var/www/html/output/wad/wad2.txt""")
os.system("""sed 's/"app":/ /g; s/"ver":/ /g' /var/www/html/output/wad/wad2.txt > /var/www/html/output/wad/wad3.txt""")
os.system("""sed -r ':r; s/("[^",]+),([^",]*)/\1 \2/g; tr; s/"//g' /var/www/html/output/wad/wad3.txt  > /var/www/html/output/wad/wad4.txt""")
os.system("""sed 's/,//' /var/www/html/output/wad/wad4.txt > /var/www/html/output/wad/wad5.txt""")
os.system("""sed '/^$/d' /var/www/html/output/wad/wad5.txt > /var/www/html/output/wad/wad6.txt""")
os.system("""awk 'NR%2{printf "%s ",$0;next;}1' /var/www/html/output/wad/wad6.txt > /var/www/html/output/wad/wad7.txt""")
os.system("""sed 's/.*null*/ /' /var/www/html/output/wad/wad7.txt > /var/www/html/output/wad/wad8.txt""")

with open("/var/www/html/output/wad/wad8.txt", "r") as f:
	search =[i.strip() for i in f.read().split("\n")]
	f.close()

for i in search:
	if i != '':
		print("\n")
		print (t.bold_bright_red("Exploit Searching For: "),i)
		print("\n")
		os.system("searchsploit " + i)

if i == '':
    print("\n")
    print(t.bold_bright_red("No Application version were found with wad module "))


#Secure Response Headers Missing Scan
print (t.bold_bright_green("""
====================================================================================
#                                  RESPONSE HEADERS INFO                           #
====================================================================================
"""))
print (t.bold_bright_cyan("[*] Usage: https://securityheaders.com/?q=[Domain]&followRedirects=on"))
print("\n")

cwd = os.getcwd()

def create_poc(url):
    ''' create HTML page of given URL '''

    code = """
<html>
   <head><title>Clickjack test page</title></head>
   <body>
     <p>"""+hostname+""" is vulnerable to clickjacking!</p>
     <iframe src="{}" width="900" height="900"></iframe>
   </body>
</html>
    """.format(url)

    with open("/var/www/html/output/" + "clickjacking" + ".html", "w") as f:
        f.write(code)
        f.close()

try:
    url = "http://" + hostname
    r = requests.get(url)
    headers = r.headers 

    host_headers = []

    for key,val in headers.items():
       print('{t.green}{:35} : {t.white}{}'.format(key, val, t=t))
       #print (t.bold_bright_green("[+] "+ response_headers))
       host_headers.append(key)


    if 'X-Frame-Options' not in headers:
        print("\n")
        print(t.bold_bright_yellow("********   Clickjacking Test   *******"))
        print("\n")
        create_poc(url)
        print (t.bold_bright_green("[+] X-Frame-Options                  :  ") + ("Website is vulnerable! to clickjacking.File has been saved to /var/www/output/clickjacking.html"))
        print("\n")
        change = cwd + "/input/webscreenshot.py"
        os.system("python " + change + " 127.0.0.1/output/clickjacking.html" + " -o " + cwd + "/output/screenshot" + hostname)

   
    print("\n")
    print(t.bold_bright_yellow("********    HTTPS BYPASS    *******"))
    print("\n")

    try:
        url = "http://" + hostname
        response = requests.get(url)
        print(t.bold_bright_green("Requested Url" + ": "),url)
        print("\n")

        if len(response.history) > 0:
            if response.history[0].status_code == 301 or 302:
                print(t.bold_bright_green("[+]HTTPS BYPASS Not Possible [" + str(response.status_code) + " ] " + " : "),response.url)
        else:
            print(t.bold_bright_red("[+]HTTPS BYPASSED [" + str(response.status_code) + " ] " + " : "),response.url)

    except Exception as e:
        print(e)

        

    secure_response_headers = ['Strict-Transport-Security', 'Expect-CT', 'X-Frame-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma' ,'Content-Security-Policy', 'Set-Cookie']
    print("\n")
    print(t.bold_bright_yellow("******* Missing Response Headers *******"))
    print("\n")
    for i in secure_response_headers:
        if i not in host_headers:
            print(t.bold_bright_red("[-] " + i ))

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
    os.system("sslscan --no-fallback " + hostname + " > " + "/var/www/html/output/sslscan.txt")
    os.system("cat /var/www/html/output/sslscan.txt")
    scan_info(1,hostname)
    print("\n")
    os.system("cat /var/www/html/output/sslscan.txt|aha --word-wrap --black >> /var/www/html/output/SSLScan.html")
    print("\n")
    change = cwd + "/input/webscreenshot.py"
    os.system("python " + change + " 127.0.0.1/output/SSLScan.html" + " -o " + cwd + "/output/screenshot/"+hostname)
	
except Exception as e:
	print(e)

#DNS Enumeration
print (t.bold_bright_green("""
====================================================================================
#                                     DNS Enumeration                              #
====================================================================================
"""))
try:
    print (t.bold_bright_cyan("[*] Usage: dnsenum --enum [Domain]"))
    print("\n")
    os.system("dnsenum --enum " + hostname + " > " + "/var/www/html/output/dns_enum.txt")
    os.system("cat /var/www/html/output/dns_enum.txt")
    scan_info(2,hostname)
    os.system("cat /var/www/html/output/dns_enum.txt|aha --word-wrap >> /var/www/html/output/dns_enum.html")
    print("\n")
    change = cwd + "/input/webscreenshot.py"
    os.system("python " + change + " 127.0.0.1/output/dns_enum.html" + " -o " + cwd + "/output/screenshot/"+hostname)
	
except Exception as e:
	print(e)

#Nmap TCP
print (t.bold_bright_green("""
====================================================================================
#                                    Nmap TCP                                      #
====================================================================================
"""))
print (t.bold_bright_cyan("[*] Usage: nmap [Options] [IP]"))
print("\n")

def nmap_scan(nmap_tcp):
    
    nmap_commands = ["","nmap -Pn -F -T4 ","nmap -Pn -F -sV -O -T4 ","nmap -Pn -sC -sV -O -T4 ","nmap -Pn -T4 -A -p 1-49151 "]
    try:
        os.system(nmap_commands[nmap_tcp] + IP + " > " + "/var/www/html/output/nmap_tcp.txt" )
        os.system("cat " + "/var/www/html/output/nmap_tcp.txt " + "| egrep -i 'state|open|filtered' " + " > " + "/var/www/html/output/nmap_tcp1.txt")
        os.system("cat " + "/var/www/html/output/nmap_tcp1.txt")
        scan_info(3,hostname)
        os.system("cat /var/www/html/output/nmap_tcp.txt|aha --word-wrap >> /var/www/html/output/Nmap_TCP.html")
        print("\n")
        change = cwd + "/input/webscreenshot.py"
        os.system("python " + change + " 127.0.0.1/output/Nmap_TCP.html" + " -o " + cwd + "/output/screenshot/"+hostname)
    except Exception as e:
        print(e)

nmap_scan(int(nmap_tcp))

#Nmap UDP
print (t.bold_bright_green("""
====================================================================================
#                                    Nmap UDP                                      #
====================================================================================
"""))
print (t.bold_bright_cyan("[*] Usage: nmap [Options] [IP]"))
print("\n")

def nmap_udp_scan(nmap_udp):

    nmap_udp_commands = ["","nmap -Pn -F -T4 -sU ","nmap -Pn -F -sV -sU -O -T4 ","nmap -Pn -sC -sV -sU -O -T4 ","nmap -Pn -T4 -sU -A -p 1-49151 "]
    try:
        os.system(nmap_udp_commands[nmap_udp] + IP + " > " + "/var/www/html/output/nmap_udp.txt" )
        os.system("cat " + "/var/www/html/output/nmap_udp.txt " + "| egrep -i 'state|open|filtered' " + " > " + "/var/www/html/output/nmap_udp1.txt")
        os.system("cat " + "/var/www/html/output/nmap_udp1.txt")
        scan_info(4,hostname)
        os.system("cat /var/www/html/output/nmap_udp.txt|aha --word-wrap --black >> /var/www/html/output/Nmap_UDP.html")
        print("\n")
        change = cwd + "/input/webscreenshot.py"
        os.system("python " + change + " 127.0.0.1/output/Nmap_UDP.html" + " -o " + cwd + "/output/screenshot/" + hostname)
    except Exception as e:
        print(e)

nmap_udp_scan(int(nmap_udp))

#Robots.txt
print (t.bold_bright_green("""
====================================================================================
#                                    ROBOTS_TXT INFO                               #
====================================================================================
"""))
time.sleep(1)
concurrent = 10

def robot():
	while True:
		final_url = "http://" + hostname + q.get()
		response = requests.get(final_url)
		robot1(response.status_code,final_url,response.url)
		q.task_done()
			

def robot1(status,url,redirect):
	global t
	
	if status == 200:
		time.sleep(0.5)
		print (t.bold_bright_yellow("[+]Status_Code [" + str(status) + "] "  + "  : " + url + " --> "),redirect )
	elif status == 401:
		time.sleep(0.5)
		print (t.bold_bright_red("[+]Status_Code [" + str(status) + "] "  + "  : " + url + " --> "),redirect )
	if status == 403:
		time.sleep(0.5)
		print (t.bold_bright_red("[+]Status_Code [" + str(status) + "] "  + "  : " + url + " --> "),redirect )
	else:
		pass


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
        with open("/var/www/html/output/robot1.txt", "wb") as f:
            f.write(read)
            f.close()
            scan_info(5,hostname)
            os.system("cat /var/www/html/output/robot1.txt " + " | grep -i 'allow' " + " | awk '{print $2}' " + " > " + "/var/www/html/output/Robots.html")
            with open("/var/www/html/output/Robots.html", "r") as f:
                url	= f.read().split()
                f.close()
            change = cwd + "/input/webscreenshot.py"
            os.system("python " + change + " 127.0.0.1/output/Robots.html" + " -o " + cwd + "/output/screenshot/"+hostname)
            print("\n")
            for i in url:
                q.put(i.strip())
            q.join()
except urllib.error.HTTPError as e:
    print (t.bold_bright_red("Robots.txt is Not Configured[" + str(e.code) + "]" + ": "),url)


#Open-Redirection
print (t.bold_bright_green("""
====================================================================================
#                                   Open-Redirection                              #
====================================================================================
"""))
time.sleep(1)
concurrent = 10
print (t.bold_bright_cyan("[*] Usage: https://hostname/[Payloadlist]"))
print("\n")
def open_redirection():
	while True:
		try:
			word = q.get()
			test_url = target_url  + word
			#headers = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0" }
			response = requests.get(test_url, allow_redirects=True)
			res_code(response.status_code,test_url,response.url)
			q.task_done()
		except requests.exceptions.ConnectionError as e:
			q.task_done()
			pass


def res_code(status,url,redirect):
	try:
		if status == 200:
			time.sleep(0.5)
			print (t.bold_bright_yellow("[+]Status_Code [" + str(status) + "] "  + "  : " + url + " --> "),redirect )
		else:
			time.sleep(0.5)
			print (t.bold_bright_red("[+]Status_Code [" + str(status) + "] "  + "  : " + url + " --> "),redirect )

	except Exception as e:
		print(e)

q = Queue(concurrent * 2)

for i in range(concurrent):
	th2 = Thread(target=open_redirection)
	th2.daemon = True
	th2.start()

target_url = "http://" + hostname

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


#Sub-Domain Finding
print (t.bold_bright_green("""
====================================================================================
#                                Sub-Domain                                        #
====================================================================================
"""))
time.sleep(1)
concurrent = 10

def doWork():
	while True:
		try:
			netloc = q.get()
			url = "http://" + netloc
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

def cname(c_url):
   try:
      result = dns.resolver.query(c_url, 'CNAME')
      for cnameval in result:
         return ' CNAME:', cnameval.target
   except:
       return "error2", c_url

def nmap_fun(url1):
	
	IP = socket.gethostbyname(url1)

	os.system("nmap -Pn -F -T4 " + IP + " > " + "/var/www/html/output/nmap/nmap_tcp.txt" )
	os.system("cat /var/www/html/output/nmap/nmap_tcp.txt | egrep -i 'state|open' > /var/www/html/output/nmap/nmap_tcp1.txt")
	os.system("""cat /var/www/html/output/nmap/nmap_tcp1.txt | sed 's/[^0-9]*//g' > /var/www/html/output/nmap/nmap_tcp2.txt""")
	os.system("""cat /var/www/html/output/nmap/nmap_tcp2.txt | sed '/^$/d' > /var/www/html/output/nmap/nmap_tcp3.txt""")
	os.system("""cat /var/www/html/output/nmap/nmap_tcp3.txt | sed '$!s/$/,/' > /var/www/html/output/nmap/nmap_tcp4.txt""")
	os.system("""cat /var/www/html/output/nmap/nmap_tcp4.txt | tr -d '\n'  > /var/www/html/output/nmap/nmap_tcp5.txt""")

	with open("/var/www/html/output/nmap/nmap_tcp5.txt", "r")as f:
		order = f.read()
		f.close()
		return "PORT: ", order

def doSomethingWithResult(status, url):
	url1 = url.replace("http://","")
	if status == 200:
		order = nmap_fun(url1)
		time.sleep(1)
		print(t.bold_bright_yellow("[+]Status_Code [" + str(status) + "] "  + "  : " + url + " : "),str(order))
	elif status == 404:
		c_name = cname(url1)
		time.sleep(1)
		print(t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : " + url + " : "), str(c_name))
	elif(status != 200 and status != 404):
		pass
    
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
sub2 = data["domain_siblings"]
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
time.sleep(1)
concurrent = 10
print (t.bold_bright_cyan("[*] Usage: https://hostname/[Wordlist]"))
print("\n")
def critical_file_found():
	while True:
		try:
			word = q.get()
			test_url = target_url + "/" + word
			#headers = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0" }
			response = requests.get(test_url, allow_redirects=True)
			code(response.status_code,test_url,response.url)
			q.task_done()
		except requests.exceptions.ConnectionError as e:
			q.task_done()
			pass


def code(status,url,redirect):
	try:
		if status == 200:
			time.sleep(1)
			print(t.bold_bright_yellow("[+]Status_Code [" + str(status) + "] "  + "  : " + url + " --> "),redirect )
		elif status == 401:
			time.sleep(1)
			print(t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : " + url + " --> "),redirect)
		elif status == 403:
			time.sleep(1)
			print(t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : " + url + " --> "), redirect)
		else:
			pass

	except Exception as e:
		print(e)

q = Queue(concurrent * 2)

for i in range(concurrent):
	th2 = Thread(target=critical_file_found)
	th2.daemon = True
	th2.start()

target_url = "http://" + hostname

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
