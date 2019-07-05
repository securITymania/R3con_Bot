# Recon_Bot
>R3con_Bot is a all in one recon tool that will help your Recon process give a boost. It is mainley aimed to automate the whole process of recon and save the time that is being wasted in doing all this stuffs manually. 

#Current Version:

>v1.2

#Operating Systems supported:

>Kali Linux

#Features:

>Multithreading

>Screenshot has been taken automatically.

#Module:

>IP Finder

>Whois

>Fingerprinting Server Version

>Exploit Search

>Secure Response Headers Missing check

>Clickjacking

>HTTPS BYPASS

>Weak Ciphers Scan

>DNS Enumeration

>#Nmap TCP

>Fast scan[Top 100 port]

>Fast scan with version detection and operating system detection

>Intense scan with services,version and operating system detection

>All Port scan with services,version operating system detection

>#Nmap UDP

>Fast scan[Top UPD port]

>Fast scan with version detection and operating system detection

>Intense scan with services,version and operating system detection

>All Port scan with services,version operating system detection

>Robots.txt

>Sub-Domain Enumeration

>Critical File Found

>Open-Redirection Check

>Web crawler

#Installation:

>git clone https://github.com/narenndhra/R3con_Bot.git

>cd R3con_Bot

>apt-get install aha

>apt-get install phantomjs

>pip3 install -r requirements.txt

>pip install wad

>pip install blessings

>Open the Recon_Bot.py file and change the apikey found at lines no '580'. To get the apikey, reference https://ithemes.com/security/how-to-malware-scan-api-key-with-virustotal/

#Example Usage:

>python3 R3con_Bot.py -h

>python3 Recon_Bot.py -d test.com -t 1 -u 1 -s 0

>python3 R3con_Bot.py -d[domain] testphp.vulnweb.com -t[tcp-scan] 1[1-4 type of scan mode] -u[udp-scan] 1[1-4 type of scan mode] -s[subdomain scan] 0[0 means skip subdomain scan and 1 mean scan subdomain]
