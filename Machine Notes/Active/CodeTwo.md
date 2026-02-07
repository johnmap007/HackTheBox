Tags: 
# **Nmap Results**

```text
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-20 21:05 EDT
Nmap scan report for 10.10.11.82
Host is up (0.014s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodeTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.62 seconds
```
<br>
<br>

# **Service Enumeration**
First look at the site:

![[Pasted image 20250820211127.png]]

We have the option to download the app, which gives us a zip file. I extract it and get the python source code:

![[Pasted image 20250820211024.png]]

First, I'll register an account on the site with the creds `test:test`. This is the dashboard:

![[Pasted image 20250820211245.png]]

The last "code" machine had a python sandbox escape vulnerability. Maybe this JavaScript code editor is similar. 

The following lines in the source code is where the vulnerability arises:

```python
@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

```

<br>
<br>
# **Exploitation**
## **Initial Access**
Everything we type in the code editor is passed to js2py's `eval_js()` method with absolutely no input sanitization of any sort. Furthermore, there is a CVE for this library explaining how the module exposes a reference to some hidden python internals by calling the JS method `getOwnPropertyNames()`. An attacker can use this to traverse through the object hierarchy and enumerate loaded modules. Combined, this allows for an easy sandbox escape attack leading to RCE by finding subprocess and invoking Popen. This [GitHub](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape/tree/main) repo holds a POC script for the CVE.

Using the exploit code, we log in as **app**. There is a sqlite3 database in our current directory under the folder "instance" containing creds for **marco**, who is the next user we need to log in as:

![[Pasted image 20250822134702.png]]

hashes.com reveals the password to be `sweetangelbabylove`, and I successfully logged in as him through SSH:

![[Pasted image 20250822134930.png]]
<br>
<br>
# **Privilege Escalation**  
Marco is allowed to execute a backup command called `npbackup-cli` with sudo, as determined by the output of `sudo -l`. In the help message, it says it requires a config file, which is already in the home directory, and is named **npbackup.conf**:

```
conf_version: 3.0.1                   
audience: public        
repos:                                    
  default:                                   
    repo_uri:             __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__      
    repo_group: default_group      
    backup_opts:
      paths:               
      - /home/app/app/
      source_type: folder_list     
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password:
      __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {} 
    is_protected: false            
```

The important line to change here is just under paths. We want to back up the **/root** directory and see if there's a private key under .ssh.

After modifying the file, execute the command with the `-b` or `--backup` flag to initiate the backup:

![[Pasted image 20250822145627.png]]

Then execute `sudo npbackup-cli --list snapshots` and note down the id of the backup you just created so you can access it. Once you have the ID, execute `sudo npbackup=cli --dump /root/.ssh/id_rsa --snapshot-id <yoursnapshotID>` to dump the contents of root's SSH private key, which you then copy to your machine and use to SSH in:

![[Pasted image 20250822150632.png]]

![[Pasted image 20250822150655.png]]
<br>
<br>
# Skills Learned
- The box was extremely similar to the first Code box, so there wasn't really anything new other than escaping a different sandbox environment for foothold and abusing a backup utility for root.
	- The web app's code editor allowed executing JS using a python library called **js2py**. The specific version in use had a CVE (specifically [CVE-2024-28397](https://attackerkb.com/topics/H5KLg53AIu/cve-2024-28397)) and didn't check user input, unlike the first code machine where it was only a lack of input sanitization that allowed for RCE.
<br>
<br>
# Proof of Pwn
https://labs.hackthebox.com/achievement/machine/391579/692