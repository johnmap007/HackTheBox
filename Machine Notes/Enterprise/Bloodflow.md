Tags: #Very-Easy #Linux #Nginx #n8n #Arbitrary-File-Read #Hidden-Subdomains #RCE 
# **Nmap Results**

```text
Nmap scan report for 10.129.234.54
Host is up (0.020s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp   open     http    nginx 1.24.0 (Ubuntu)
|_http-title: AI JobMatch - Find Your Perfect Career Match
|_http-server-header: nginx/1.24.0 (Ubuntu)
5678/tcp filtered rrac
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun  1 17:06:53 2026 -- 1 IP address (1 host up) scanned in 10.61 seconds
```
<br>
<br>

# **Service Enumeration**
Head over to the web server in your browser:

![[Pasted image 20260601171155.png]]

If you scroll down, you'll see a form to join a waitlist:

![[Pasted image 20260601171826.png]]

This is what the request looks like after you fill out all the fields and submit:

![[Pasted image 20260601171715.png]]

The site has a domain "bloodflow.htb" and a subdomain of "n8n.bloodflow.htb". Add these to /etc/hosts.

Here's what we see at n8n.bloodflow.htb:

![[Pasted image 20260601172117.png]]

If you hit "more info", a sidebar pops out from the left and tells us the current version is 1.65.0:

![[Pasted image 20260601172206.png]]
<br>
<br>
# **Exploitation**
## **Initial Access**
This version is vulnerable to CVE-2026-21858, aka "ni8mare". It allows an attacker to perform arbitrary file read as a result of Content-Type confusion. With this, you can exfiltrate the n8n config file and database contents, giving you enough info to forge the admin's JWT. After that, you can abuse n8n's legitimate functionality to execute system commands and obtain a remote shell. This [GitHub](https://github.com/Chocapikk/CVE-2026-21858) poc chains these vulnerabilities and automates the whole process.

After running it, we get a shell as **n8n**:

![[Pasted image 20260601175353.png|697]]



<br>
<br>
# **Privilege Escalation**  
This box didn't have a PE step
<br>
<br>
# Skills Learned
- Not much aside from what "ni8mare" is and how it works 
<br>
<br>
# Proof of Pwn
![[Pasted image 20260601175827.png]]