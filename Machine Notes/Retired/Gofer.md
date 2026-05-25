Tags: #Hard #Linux #Apache #Hidden-Subdomains 
# **Nmap Results**

```text
Nmap scan report for 10.129.17.48
Host is up (0.015s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE    SERVICE     VERSION
22/tcp  open     ssh         OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 aa:25:82:6e:b8:04:b6:a9:a9:5e:1a:91:f0:94:51:dd (RSA)
|   256 18:21:ba:a7:dc:e4:4f:60:d7:81:03:9a:5d:c2:e5:96 (ECDSA)
|_  256 a4:2d:0d:45:13:2a:9e:7f:86:7a:f6:f7:78:bc:42:d9 (ED25519)
25/tcp  filtered smtp
80/tcp  open     http        Apache httpd 2.4.56
|_http-title: Did not follow redirect to http://gofer.htb/
|_http-server-header: Apache/2.4.56 (Debian)
139/tcp open     netbios-ssn Samba smbd 4
445/tcp open     netbios-ssn Samba smbd 4
Service Info: Host: gofer.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2026-04-07T23:14:26
|_  start_date: N/A
|_nbstat: NetBIOS name: GOFER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.67 seconds

```
<br>
<br>

# **Service Enumeration**
First look at the site:

![[Pasted image 20260407191849.png]]

Gobuster found the **proxy.gofer.htb** subdomain, which is protected by HTTP authentication since it got 401 status while visiting it:

![[Pasted image 20260407192513.png]]

There's nothing else interesting on the webpage, so we'll move on for now.

Port 445 was open and has SMB running on it, so we'll take a look at it with `smbclient`:

![[Pasted image 20260407195944.png]]

I tried the share named "**shares**" and connected successfully. There was one folder named ".backup", and in it just one file named "mail":

![[Pasted image 20260407200341.png]]

This is what it contains:

![[Pasted image 20260407200402.png]]

They say important documents will now only be sent internally via mail because of recent phishing attempts, which kind of explains the SMTP server on port 25 and why it could be filtered. 

More importantly, it hints that the web proxy uses the `<Limit>` directive to "restrict access". The Apache docs say that this will trigger some access control to the specified resource whenever a certain method is invoked on it. So not only is it possible that not all methods require HTTP auth, but also not all resources. 

If we do a GET on proxy.gofer.htb, we get a 401 as expected, and if we change it to POST, we get the same thing. But if we try to POST somewhere other than "/", we get a 404 instead:

![[Pasted image 20260407202813.png]]

Now we just need to find a valid location. We can use `feroxbuster` again, but this time have it send POST requests instead of GET requests using the `-m` switch. 

We only get 1 result which is **/server-status**, and it gives us a 403 Forbidden.

Let's see if there are any PHP pages by passing `-x php` and using the **raft-small-words.txt** wordlist in seclists:

![[Pasted image 20260407204547.png]]

Looks like index.php is a valid page. Now let's see what Burpsuite says:

![[Pasted image 20260407204658.png]]

The server seems to accept a URL parameter. There could be an SSRF vulnerability here. Let's see what happens when we pass our machine's IP and set up a listener

![[Pasted image 20260407205512.png]]

![[Pasted image 20260407211453.png]]

The application doesn't return anything in the body other than that comment. My listener didn't catch anything either.

NOTE: This isn't supposed to happen, the listener should see a request. Something's wrong. 
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