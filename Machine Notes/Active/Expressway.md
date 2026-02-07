Tags: 
# **Nmap Results**

```text
Nmap scan report for 10.10.11.87
Host is up (0.015s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.61 seconds
```
<br>
<br>

# **Service Enumeration**
This machine is a bit odd. TCP Port 22 is the only open port on the entire thing, running the latest version of OpenSSH. Let's begin enumerating there.

I ran multiple nmap scripts for SSH against the target such as ssh-auth-methods, and ssh-brute. The server accepts **passwords** and **keypairs** for authentication, but we don't have any of that.  

ssh-brute failed to find creds using the default wordlists and another wordlist of default SSH creds I found in seclists. We've hit a dead end.

I performed a UDP scan and found a service called isakmp listening on port 500. According to this [resource](https://trainingcamp.com/glossary/isakmp/), ISAKMP is a protocol for managing Security Associations (SAs) and cryptographic keys, and is part of the Internet Key Exchange (IKE) protocol. 


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