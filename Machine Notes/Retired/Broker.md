Tags: 
# **Nmap Results**

```text
Nmap scan report for 10.129.230.87
Host is up (0.019s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.50 seconds
```
<br>
<br>

# **Service Enumeration**
Active MQ 5.15.15 on port 61616 vulnerable to **CVE-2023-46604**, an RCE vulnerability.

there's a metasploit module, search the cve with the search command and you'll find it. 

post exploitation --> log in as activemq. they can run nginx using sudo without passwd. gotta use dav_methods module or something, along with a PUT request
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