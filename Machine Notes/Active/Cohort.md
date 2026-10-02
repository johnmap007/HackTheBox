Tags: 
# **Nmap Results**

```text
Nmap scan report for 10.129.50.252
Host is up (0.021s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://cohort.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.24.0 (Ubuntu)
| tls-alpn:
|   http/1.1
|   http/1.0
|_  http/0.9
| ssl-cert: Subject: commonName=cohort.htb/organizationName=Cohort Analytics
| Subject Alternative Name: DNS:cohort.htb, DNS:*.cohort.htb
| Not valid before: 2026-06-01T18:47:07
|_Not valid after:  2126-05-08T18:47:07
|_http-title: Did not follow redirect to https://cohort.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.20 seconds
```
<br>
<br>

# **Service Enumeration**
First look at the site:

![[Pasted image 20260831230243.png]]

Client Insights looks interesting:

![[Pasted image 20260831230452.png]]

The Source URL field tries to prevent SSRF but it doesn't do it well. If you input http://127.1, that will pass just fine. Now we just need to know what we want to look at.

Feroxbuster didn't return anything, so we try running gobuster in dir mode. Feroxbuster kept skipping a bunch of results that all returned 301 status codes, and gobuster refused to run because of this. So we'll tell it to follow redirects with `-r`. The site seems to upgrade requests to HTTPS through these redirects. We also have to specify the `-k` flag to ignore certificate warnings. 

Output:

![[Pasted image 20260831232356.png]]

Now input http://127.1/status in the Source URL field and submit it:

![[Pasted image 20260831232744.png]]

There's a new subdomain here that gobuster didn't pick up earlier, add it to your /etc/hosts file. Now we're presented with this:

![[Pasted image 20260831233015.png]]

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
- When directory fuzzing, if all the results return status code 301, try following redirects instead of filtering it
<br>
<br>
# Proof of Pwn
Paste link to HTB Pwn notification after owning root