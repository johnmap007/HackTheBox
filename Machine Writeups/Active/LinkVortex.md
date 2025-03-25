Tags: 
# **Nmap Results**

```text
Nmap scan report for 10.10.11.47
Host is up (0.019s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://linkvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.77 seconds
```
<br>
<br>

# **Service Enumeration**
Nmap discovered an Apache web server with the hostname **"linkvortex.htb"** on port 80, as well as SSH listening on port 22. I added an entry to my `/etc/hosts` file and then navigated to the site. Here's what we find:

![[Pasted image 20250315200615.png]]

It looks to be a blog on computer hardware. Since we have a domain, we should run `gobuster` in vhost mode to enumerate any potential subdomains:

![[Pasted image 20250315233330.png]]

We've discovered `dev.linkvortex.htb`, so we'll go ahead and add that to our **/etc/hosts** file as well. 

Taking a look, the site is just under construction:

![[Pasted image 20250315235745.png]]

After running gobuster here, it didn't find anything at first, but then I used the **raft-medium-words.txt** wordlist and found **/.git**. Within this page, I found a config file with the following content:

```
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/TryGhost/Ghost.git
	fetch = +refs/tags/v5.58.0:refs/tags/v5.58.0
```

If we go back to **linkvortex.htb**, we see it says "Powered by Ghost" at the bottom of the page. Knowing this, we can take a look around the [repository](https://github.com/TryGhost/Ghost/tree/main) and figure out how the web page is structured and where valuable info can be stored. From the config file, we also know that the site is using Ghost **version 5.58.0**, which is also confirmed by the home page's source code:

![[Pasted image 20250316000107.png]]

In the repository, we see some interesting folders within **/ghost/admin/**, like config and app. But we need to find the sign-in page. After googling, I know that page is located at /ghost:

![[Pasted image 20250316002050.png]]

I tried inputting basic SQL injection payloads and special characters and intercepting requests with burp to analyze how to server responds to these kinds of input, but none of it seemed to change its behavior. SQLmap also didn't return anything promising and default credentials don't exist because Ghost requires users to create an account during setup. 

Maybe we missed something in the /.git page. Since directory listing is available, I'll download all files and folders to my machine and **reconstruct the git repository**. In doing so, I can use git commands to discover more info that wouldn't be visible through direct file browsing.  

So first we download everything using wget:
`wget -r -np -R index.html* http://dev.linkvortex.htb/.git/`,
* -r for recursive
* -np for excluding parent directories
* -R index.html* for excluding all files that start with index.html 

Then to actually create our repository, we run the following commands

```bash
git init
git remote add origin http://dev.linkvortex.htb/.git
git pull origin main
```

Excellent, we have a local version of this repository. Now to view changes, we run `git status`. The first part of this output catches my attention:

![[Pasted image 20250316190146.png]]

There are 2 files that could hold valuable info: **"Dockerfile.ghost"** and **"authentication.test.js"**. Further down, however, we see the same files staged for deletion. To restore them, we run: `git restore <filename>`.

There is a password in the authentication.test.js file:

![[Pasted image 20250316191526.png]]

I tried to login as admin with this, and it worked:

![[Pasted image 20250316191705.png]]

Earlier, we found out that Ghost version 5.58 was in use, and when searching for known vulnerabilities, I came across an **Arbitrary File Read** vulnerability as detailed in [this GitHub page](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028/tree/master)

The vulnerability exists because Ghost does not perform any checks on uploaded content, automatically extracts ZIP files, and allows direct access to the directory where the uploaded content is stored. This allows an attacker to create a symlink (a file pointing to another file or directory), archive it, and upload it to the server. When Ghost unzips the file, it **preserves the symlink**, and once an attacker makes a request to this location, the server returns whatever resource it was pointing to. 

The exploit script on the GitHub page does exactly that. Let's pull **/etc/passwd** first:

![[Pasted image 20250317001649.png]]

There are 2 users on the box, root and node, so our goal is to login as node.

After lots of trial and error, I found Ghost's root directory to be in **/var/lib** and was able to pull **/var/lib/ghost/config.production.json**:

```json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
```

There seems to be something locally hosted on port 2368 and a mail server on port 587.  The credentials are provided at the bottom, which we can leverage later. Unfortunately this password isn't reused by node, so we have to keep digging. 


<br>
<br>
# **Exploitation**
## **Initial Access**
Document here:
* Exploit used (link to exploit)
* Explain how the exploit works against the service
* Any modified code (and why you modified it)
* Proof of exploit (screenshot of reverse shell with target IP address output)

<br>
<br>
# **Privilege Escalation**  

Document here:
* Exploit used (link to exploit)
* Explain how the exploit works 
* Any modified code (and why you modified it)
* Proof of privilege escalation (screenshot showing ip address and privileged username)
<br>
<br>
# Skills Learned
Document here what you've learned after completing the box
<br>
<br>
# Proof of Pwn
Paste link to HTB Pwn notification after owning root