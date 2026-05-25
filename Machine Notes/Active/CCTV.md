Tags: #Easy #Linux/Ubuntu #Apache #Default-Creds #Blind-SQL-Injection #Weak-Passwords #Overprivileged-Processes #Command-Injection 
# **Nmap Results**

```text
Nmap scan report for 10.129.244.156
Host is up (0.020s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 76:1d:73:98:fa:05:f7:0b:04:c2:3b:c4:7d:e6:db:4a (ECDSA)
|_  256 e3:9b:38:08:9a:d7:e9:d1:94:11:ff:50:80:bc:f2:59 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://cctv.htb/
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.59 seconds
```
<br>
<br>

# **Service Enumeration**
First look at the site:

![[Pasted image 20260524164005.png]]

We should look at the staff login portal, which brings us this:

![[Pasted image 20260524164101.png]]

The credentials were easily guessable. They were `admin:admin`, which also turns out to be the default ones. After logging in, we get here:

![[Pasted image 20260524164202.png]]

The top right of the page tells us that the running version of ZoneMinder is **v1.37.63**. According to [this](https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-qm8h-3xvf-m7j3) GitHub post, this version is vulnerable to a boolean based blind SQL injection attack. 
<br>
<br>
# **Exploitation**
## **Initial Access**
Using `sqlmap`, we can automate the exploitation and have it dump available databases:

![[Pasted image 20260524170410.png]]

Runing `sqlmap` again but with `-D zm --tables` allows us to enumerate tables within the zm database. Only issue is that there are 43 of them, and boolean based blind attacks take eons to complete, so we'll look up the default schema. The only interesting table is the **Users** table. 

Following a similar process to enumerate columns, we see the columns **Username** and **Password**. Now we dump all the rows there with `-D zm -T Users -C Username, Password`

List of usernames:

![[Pasted image 20260524191631.png]]

and their respective password hashes, which are in the form of bcrypt:

![[Pasted image 20260524191647.png]]

hashcat found the password to admin, which we already knew was just "admin", but also mark's which was "opensesame":

![[Pasted image 20260524191550.png]]

These creds are valid for SSH login and we are now logged in as mark on the machine.
<br>
<br>
# **Privilege Escalation** 
mark doesn't have sudo privileges, there is nothing in his home directory, and nothing of interest in /opt. However, there are some interesting open ports listening locally. I port forwarded a few of them and port 8765 seems to be the most interesting one:

![[Pasted image 20260524194618.png]]

It's some kind of portal for motionEye, the GUI app for the CLI tool "motion". It's a video surveillance app. Looking in /etc, we see a **motioneye** directory. In there, there's 2 config files, motioneye.conf and motion.conf. The latter contains valid credentials for this page, which are `admin:989c5a8ee87a0e9521ec81a79187d162109282f0`. 

There isn't more to see here, but if we look back in /etc/, there's another directory called **motion**, with another config file that tells us that the installed version of the CLI tool is 4.7.1 (you also could've found this by just running `motion` with no arguments). You'll find that this version is vulnerable to command injection according to [this](https://www.exploit-db.com/exploits/52481) ExploitDB post. This is due to a lack of input sanitization on the back end, relying only on front end JavaScript to do so.

To bypass this, you just rewrite the configUiValid() method to return true unconditionally, like so:

```js
function configUiValid() {
	return true;
}
```

The vulnerable field is *image file name* under the "Still Images" tab in the camera settings. The value here is read by the motion process once it restarts after you apply changes, and it interprets all special characters as if it was shell syntax, so you can use things like command substitution:

![[Pasted image 20260525130025.png]]

Now write your reverse shell in there and set up a listener. Apply changes and have the camera take a still image. You should have caught a shell as root now:

![[Pasted image 20260525130123.png]]

That's it!
<br>
<br>
# Skills Learned
- There are 2 places where input sanitization can be implemented, front end JS and back end source code. Front end is easier to bypass because you essentially have full control over the JS that runs in your browser
<br>
<br>
# Proof of Pwn
https://labs.hackthebox.com/achievement/machine/391579/847