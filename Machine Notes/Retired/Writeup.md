Tags: 
# **Nmap Results**

```text
Nmap scan report for 10.129.18.153
Host is up (0.025s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u1 (protocol 2.0)
| ssh-hostkey: 
|   256 37:2e:14:68:ae:b9:c2:34:2b:6e:d9:92:bc:bf:bd:28 (ECDSA)
|_  256 93:ea:a8:40:42:c1:a8:33:85:b3:56:00:62:1c:a0:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Nothing here yet.
| http-robots.txt: 1 disallowed entry 
|_/writeup/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.88 seconds
```
<br>
<br>

# **Service Enumeration**
There's a web server at port 80 so we'll take a look in our browser:

![[Pasted image 20260623142409.png]]

Site seems to be under construction. It also tells us there's some DoS protection and IP banning features installed, so we'll have to throttle all scans to avoid this. 

The nmap scan said there was an entry in robots.txt, which is **/writeup/**. Let's take a look at that:

![[Pasted image 20260623143042.png]]

Towards the bottom of the page, it says "Pages are hand-crafted with vim. NOT." so we'll have to find out what this page is made of. 

The page source tells us pretty quickly:

![[Pasted image 20260623145033.png]]

There's no version information here, so we'll have to look for the source code of CMSMS. Their official site has a Subversion repo, which gives us a detailed map of where things are.

Interestingly enough, it appears that the latest version is shown in /doc/CHANGELOG.txt at the top of the file. When we go there in our browser on the target machine, we actually do see it:

![[Pasted image 20260623151135.png]]
<br>
<br>
# **Exploitation**
## **Initial Access**
This specific version is vulnerable to an unauthenticated SQL Injection attack, which is labeled CVE-2019-9053. A PoC is available on ExploitDB:

![[Pasted image 20260623151401.png]]

After running it, it extracted some useful information:

![[Pasted image 20260623153055.png]]

CMS made simple calculates hashes by prepending the salt to the password then hashing the entire thing. This corresponds with hashcat mode 20. 

The password ends up being `raykayjay9` and we can log in as "jkr" via SSH with these creds. 

<br>
<br>
# **Privilege Escalation**  
The user "jkr" is part of a group called "staff". This is a special group in linux where members are allowed to  make local modifications to the system without root privileges, meaning jkr can add, remove, and modify scripts in the /usr/local directory. 

If you look at the path variable, you'll find that /usr/local/bin is the very first entry:

![[Pasted image 20260623162133.png]]

Now, if there is a root process that executes a command without using an absolute path, we can force it to execute a custom script placed in /usr/local/bin. To find such a process, we use `pspy`.

![[Pasted image 20260623164737.png]]

When we log in to jkr from another window, we see that a command called run-parts is executed using a relative path.

Write the following to /usr/local/bin/run-parts:

```bash
#!/bin/bash

mkdir /root/.ssh
echo '<ssh public key here>' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

This will insert your public key into root's list of authorized keys so you can log in via SSH. 

Now trigger the script by logging in as jkr again. After that, your public key should be there and you should be able to log in as root:

![[Pasted image 20260623165221.png]]
<br>
<br>
# Skills Learned
- If you encounter a web technology that you don't recognize, such as a CMS, search for the source code to understand its structure. If you can find a version, look for that specific release's source code
- When inspecting processes with pspy, try logging out and logging back in again to the current user with SSH. The bash profile can do something interesting that can be exploited 
<br>
<br>
# Proof of Pwn
Paste link to HTB Pwn notification after owning root