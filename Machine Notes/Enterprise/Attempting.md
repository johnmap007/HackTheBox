Tags: 
# **Nmap Results**

```text
Nmap scan report for 10.129.228.238
Host is up (0.021s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 35:5c:20:86:4a:23:0f:27:26:05:53:fa:13:98:f8:6f (RSA)
|   256 a7:65:4a:9a:4c:e3:d4:b0:fd:c9:6d:8e:ff:5e:1d:d5 (ECDSA)
|_  256 70:41:86:a1:f4:d1:d5:a1:55:55:6f:fb:8d:3b:75:d1 (ED25519)
80/tcp   open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: AttempTing Login
|_Requested resource was login.php
8080/tcp open  http    nginx 1.18.0
| http-title: Mailu-Admin | FreeMail
|_Requested resource was /sso/login
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-open-proxy: Proxy might be redirecting requests
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.18 seconds

```
<br>
<br>

# **Service Enumeration**
Here's what we see first when we go to the web app in our browser:

![[Pasted image 20260606212641.png]]

The main.js file contains some interesting lines at the beginning:

```js
window.onload = async function() {
  reg = document.getElementById("register");
  if (typeof(reg) != 'undefined' && reg != null) {
    reg.disabled = true;
    const response = await fetch('http://api.attempting.htb/account', {
      method: 'POST',
      body: '{"action": "can_register", "encrypt": false}',
      headers: {
        'Content-Type': 'application/json'
      }
    })
```

It seems to contact an API at `http://api.attempting.htb/account` to verify whether registration is allowed or not. When I inspect this request myself with burpsuite, the response returns 0, meaning false, or not allowed. But by changing the value of the **action** parameter to just "register", we get this:

![[Pasted image 20260606213223.png]]

After supplying the email parameter, it also asks for first and last name, password, and confirm password. However, after supplying all of these arguments with values, it returns an error and a hash:

![[Pasted image 20260606213622.png]]
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