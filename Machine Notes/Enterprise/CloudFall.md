Tags: 
# **Nmap Results**

```text
Nmap scan report for 10.129.96.80
Host is up (0.017s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f4:b2:ec:bb:21:7c:2f:bc:5a:c1:59:d3:6b:eb:b6:36 (RSA)
|   256 b1:67:4a:a6:e3:2c:7f:f8:94:70:b6:25:1a:01:14:5e (ECDSA)
|_  256 10:05:fe:64:e2:16:2c:49:2a:95:ba:c6:25:94:a1:c9 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://cloudfall.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.28 seconds
```
<br>
<br>

# **Service Enumeration**
Head over to the web server in your browser:

![[Pasted image 20260606192930.png]]

I ran `gobuster` in vhost mode and found the subdomain `s3.cloudfall.htb` with status 302. After adding that to our /etc/hosts file and checking it out, we get this:

![[Pasted image 20260606193608.png]]

It redirects us to the main domain at the page 403.html, which doesn't seem to exist. 

If you click sign in on the main page, you get this:

![[Pasted image 20260616134212.png]]

I created an account with username = test, email = test@example.com, and password = test, but logging in to that account doesn't work. The site just refreshes and the end of the url says "invalid creds"
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