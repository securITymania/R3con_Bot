#!/usr/bin/env python
import socket
import os
import requests
import time
import re
import sys
import itertools
import threading
import optparse
import dns.resolver
import urllib.error
from urllib.parse import urlparse
from urllib.parse import urljoin
from urllib import parse
from urllib.request import urlopen, Request
from threading import Thread
from queue import Queue
from texttable import Texttable
from blessings import Terminal

parser = optparse.OptionParser()
parser.add_option("-d","--domain", dest="hostname", help="Give the target domain name ")
parser.add_option("-s","--subdomain", dest="subdomain", help="These options is used to scan subdomains using 0 as skip and 1 as scan subdomains")
parser.add_option("-t","--nmap_tcp", dest="nmap_tcp", help="Nmap TCP Scan type options from [1-4]             1.Fast scan[Top 100 port scan]                      2.Fast scan with service,os & version detection         3.Intense scan with service,os & version detection     4.All port scan with service,os & version detection")
parser.add_option("-u","--nmap_udp", dest="nmap_udp", help="Nmap UDP Scan type options from [1-4]             1.Fast scan[Top 100 port scan]                      2.Fast scan with service,os & version detection         3.Intense scan with service,os & version detection        4.All port scan with service,os & version detection")

(options, arguments) = parser.parse_args()

host = options.hostname

if host.startswith('http://'):
    hostname = host.replace("http://","")
elif host.startswith('https://'):
    hostname = host.replace("https://","")
else:
    hostname = options.hostname

nmap_tcp = options.nmap_tcp
nmap_udp = options.nmap_udp
subdomain = options.subdomain

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
zero = "[#] Created By   :"
first = "Mr.Robot"
second = "IamNotRobot"
print('{t.bold_bright_cyan}{} {t.bold_bright_red}{} , {t.bold_bright_red}{}'.format(zero,first, second, t=t))
print (t.bold_bright_cyan("[#] Tool Support : R3con in Depth and Fully Automated"))
print (t.bold_bright_cyan("[#] Version      : 1.2")) 
print("\n")

done = False
#here is the animation
def animate():
    for c in itertools.cycle(['|', '/', '-', '\\',]):
        if done:
            break
        sys.stdout.write('\r[#] Hold on Apache Server is starting ......' + c)
        sys.stdout.flush()
        time.sleep(0.1)

t = threading.Thread(target=animate)
t.start()
time.sleep(3)
done = True

os.system("service apache2 start")
os.system("mkdir /var/www/html/output/wad")
os.system("mkdir /var/www/html/output")
os.system("mkdir /var/www/html/output/nmap")
os.system("clear")

#Scan Information

def scan_info(module,target_host):
    modules = ('Whois','Wad','searchsploit','secure_response_headers','SSLScan','dns_enum','Nmap_TCP','Nmap_UDP')
    f = open('/var/www/html/output/'+modules[module]+'.html', 'w')
    f.write("<h3>"+modules[module]+ " Scan Result: "+hostname+"</h3>")
    f.close()

t = Terminal()

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
    os.system("wad -u" + "http://" + hostname + " -f csv -o /var/www/html/output/wad/wad.csv 1> /dev/null")
    print("\n")
    time.sleep(8)
    
    f = open("/var/www/html/output/wad/wad.csv","r")
    a = f.readlines()
    tt = Texttable()
    table = []
    versions = {}
    tt.set_cols_width([35,35,15,45])
    for i in a:
        i = i.split(",",3)
        versions.update( {i[1] : i[2]} ) 
        table.append(i)
    tt.add_rows(table)
    with open('/var/www/html/output/wad/wad.txt', 'w') as f:
        print('', tt.draw(), file=f)
        tt.reset()
        f.close()
    os.system("cat /var/www/html/output/wad/wad.txt")
    scan_info(1,hostname)
    os.system("cat /var/www/html/output/wad/wad.txt|aha --black --word-wrap >> /var/www/html/output/Wad.html")  
    print("\n")
    change = cwd + "/input/webscreenshot.py"
    os.system("python " + change + " 127.0.0.1/output/Wad.html" + " -o " + cwd + "/output/screenshot/" + hostname)
        
except Exception as e:
    print(e)

#Exploit Search
print (t.bold_bright_green("""
====================================================================================
#                                     Exploit Search                               #
====================================================================================
"""))
print (t.bold_bright_cyan("[*] Usage: searchsploit [(Application) (version)]"))

os.system("echo '' > /var/www/html/output/searchsploit.txt")
for key,val in versions.items():
    if val is not "":
        cmd = 'searchsploit '+key+" "+val+" >> /var/www/html/output/searchsploit.txt"
        os.system(cmd)
    else:
        pass
scan_info(2,hostname)
os.system("cat /var/www/html/output/searchsploit.txt")
print("\n")
os.system("cat /var/www/html/output/searchsploit.txt|aha  --word-wrap >> /var/www/html/output/searchsploit.html")
change = cwd + "/input/webscreenshot.py"
os.system("python " + change + " 127.0.0.1/output/searchsploit.html" + " -o " + cwd + "/output/screenshot/"+hostname)


#Secure Response Headers Missing Scan
print (t.bold_bright_green("""
====================================================================================
#                                  RESPONSE HEADERS INFO                           #
====================================================================================
"""))
print (t.bold_bright_cyan("[*] Usage: https://securityheaders.com/?q=[Domain]&followRedirects=on"))
banner = t.bold_bright_green("""
====================================================================================
#                                  RESPONSE HEADERS INFO                           #
====================================================================================
""")

with open('/var/www/html/output/response.txt', 'w') as f:
    print(banner, file=f)
    f.close()

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
        if key != 'Date' and key != 'Link' and key != 'X-UA-Compatible' and key != 'Content-language' and key != 'Expires' and key != 'Vary' and key != 'Cache-Tags' and key != 'Last-Modified' and key != 'ETag' and key != 'Transfer-Encoding' and key != 'Connection' and key != 'Accept-Ranges' and key!= 'Content-Encoding' and key != 'Content-Language' and key != 'Content-Type':
            domainheaders = '{t.green}{:35} :{t.white}{}'.format(key, val, t=t)
            print('{t.bold_bright_green}{:35} :  {t.bold_bright_white}{}'.format(key, val, t=t))
            host_headers.append(key)
            with open('/var/www/html/output/response.txt', 'a') as f:
                print(domainheaders, file=f)
                f.close()

    if 'X-Frame-Options' not in headers:
        print("\n")
        print(t.bold_bright_yellow("********   Clickjacking Test   *******"))
        print("\n")
        create_poc(url)
        print (t.bold_bright_green("[+] X-Frame-Options                  :  ") + ("Website is vulnerable! to clickjacking.File has been saved to /var/www/output/clickjacking.html"))
        print("\n")
        change = cwd + "/input/webscreenshot.py"
        os.system("python " + change + " 127.0.0.1/output/clickjacking.html" + " -o " + cwd + "/output/screenshot/" + hostname)

   
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

    with open('/var/www/html/output/response.txt', 'a') as f:
        print("\n\n", file=f)

    secure_response_headers = ['Strict-Transport-Security', 'Expect-CT', 'X-Frame-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma' ,'Content-Security-Policy', 'Set-Cookie']
    print("\n")
    banner2 = t.bold_bright_yellow("******* Missing Response Headers *******")
    print(t.bold_bright_yellow("******* Missing Response Headers *******\n"))
    print("\n")
    with open('/var/www/html/output/response.txt', 'a') as f:
        print(banner2, file=f)

    for i in secure_response_headers:
        if i not in host_headers:
            missings = '{t.red}{}'.format(i, t=t)
            print(t.bold_bright_red("[-] " + i))
            with open('/var/www/html/output/response.txt', 'a') as f:
                print(missings, file=f)
    scan_info(3,hostname)
    os.system("cat /var/www/html/output/response.txt|aha --word-wrap  >> /var/www/html/output/secure_response_headers.html")
    print("\n")
    change = cwd + "/input/webscreenshot.py"
    os.system("python " + change + " 127.0.0.1/output/secure_response_headers.html" + " -o " + cwd + "/output/screenshot/"+hostname)

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
    scan_info(4,hostname)
    print("\n")
    os.system("cat /var/www/html/output/sslscan.txt|aha --word-wrap  >> /var/www/html/output/SSLScan.html")
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
    scan_info(5,hostname)
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
        scan_info(6,hostname)
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
        scan_info(7,hostname)
        os.system("cat /var/www/html/output/nmap_udp.txt|aha --word-wrap  >> /var/www/html/output/Nmap_UDP.html")
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
            os.system("cat /var/www/html/output/robot1.txt " + " | grep -i 'allow' " + " | awk '{print $2}' " + " > " + "/var/www/html/output/robot2.txt")
            with open("/var/www/html/output/robot2.txt", "r") as f:
                url	= f.read().split()
                f.close()
           
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
if subdomain == '1':
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

elif subdomain == '0':
    print (t.bold_bright_red("Sub-domains scan has been skiped by the user"))


#Critical-File Finding
print (t.bold_bright_green("""
====================================================================================
#                                Critical-File Found                              #
====================================================================================
"""))
time.sleep(1)
concurrent = 10
url = "http://" + hostname
print (t.bold_bright_yellow("Target: "),url)
print("\n")
print(t.bold_bright_cyan(""))
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
			print(t.bold_bright_yellow("[+]Status_Code [" + str(status) + "] "  + "  : " + url + " --> "),redirect )
		elif status == 401:
			print(t.bold_bright_red("[-]Status_Code [" + str(status) + "] "  + "  : " + url + " --> "),redirect)
		elif status == 403:
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
