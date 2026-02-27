Tags: #Linux/Debian  #Medium #Nginx #Argument-Injection #Verbose-Error-Messages #File-Upload #Overpermissive-Files #Sudo-Misconfiguration
# **Nmap Results**

```text
Nmap scan report for 10.10.11.67
Host is up (0.050s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
|_  256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Did not follow redirect to http://environment.htb
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.04 seconds
```
<br>
<br>

# **Service Enumeration**
First look at the site:

![[Pasted image 20250726184328.png]]

Gobuster didn't find any hidden subdomains but Feroxbuster revealed an interesting page called **/mailing** and **/upload**, which both return an error page similar to the one below:

![[Pasted image 20250726185007.png]]

There is also a login panel at **/login**:

![[Pasted image 20260222174646.png]]

If you scroll down on the home page, you can submit your email to be added to a mailing list:

![[Pasted image 20260223204625.png]]

When you hit the button, it actually does send a POST request to **/mailing** with 2 parameters, email and token:

![[Pasted image 20260223204723.png]]

Both error pages reveal that Laravel version 11.30.0 is the web framework in use, which is vulnerable to **CVE-2024-52301**, an argument injection vulnerability where you can switch the environment of the web server to one meant for debugging, testing, or whatever else is set. Might be useful later.

> [!info] CVE-2024-52301 explained
> The reason for the vulnerability is because of the `register_argc_argv()` method in PHP. This populates the `$_SERVER['argv']` array with any arguments it can see, whether via the command line or through a request. This used to be a standardized thing used by many developers because they liked the flexibility of modifying server behavior on the fly just by injecting certain parameters in the URL. 
> 
> An attacker only needs to inject the `--env` argument set to some specially defined environment (like debug, test, dev, etc.) and the server will likely return a very different version of the site that includes sensitive data not meant to be seen.
<br>
<br>
# **Exploitation**
## **Initial Access**
Going back to the login page, let's take a look at what a request would look like if we tried authenticating:

![[Pasted image 20260223230405.png]]

If we can cause an error on the server, we might be able to see a stack trace including source code, or some other important details. PHP is usually pretty verbose unless configured otherwise. Let's try omitting the email parameter in this request.

This is what the server responds with:

![[Pasted image 20260223225937.png]]

The server tried reading the value from the email parameter, but we didn't even specify it, so it errored out and gave us a bit more source code to look at beyond the offending line. 

Towards the bottom there's a weird check for the **keep_loggedin** variable even after the code above it seems to be enough. It's cut short though. Maybe we can cause another error that occurs further down so it'll give us more code.

Let's try setting the **remember** parameter to "nothing", just anything that's not true or false so that the code above it doesn't initialize the variable. 

![[Pasted image 20260223230235.png]]

Seems like it was nothing, but just below it there's a block that checks if the environment is set to "preprod", and if so, it logs us in immediately as the admin. We can abuse that argument injection CVE we found a while ago. 

All we have to do is insert `--env=preprod` as a URL parameter after we send a login request. None of the data matters. So the POST header should look like `POST /login?--env=preprod`.

After sending it, we get logged in:

![[Pasted image 20260223232009.png]]

The profile tab allows us to upload a profile picture, there could be a file upload vuln here.

[CVEdetails](https://www.cvedetails.com/vulnerability-list/vendor_id-16542/Laravel.html) shows a list of laravel vulnerabilities, one of them being **CVE-2025-27515** where file uploads aren't properly validated to be of an acceptable type, so malicious files can be uploaded. 

I'll upload a regular php file with the line `<?php system($_GET['cmd']); ?>` but also with the magic bytes for a JPEG file at the beginning (which are `FF D8 FF E0`) to fool the server into thinking it really is an image when it's not. 

This [post](https://www.miggo.io/vulnerability-database/cve/CVE-2025-27515) talks more about the CVE, explaining that characters such as '.', '\*', and '0' are stripped from the end of files and break validation logic since the checks succeed after it has removed any. 

Upload malicious file, modify filename in burp to be "exploit.jpg.php." (notice the dot at the end) and send request. The server will return the location where the file is saved, type it in the browser with the cmd parameter. 

![[Pasted image 20260226183731.png]]

![[Pasted image 20260226183833.png]]

Execute reverse shell one liner with listener active and you get a shell as **www-data**:

![[Pasted image 20260226184000.png]]

In the webroot dir, there's a "database" folder containing a SQLite3 database and a "users" table. It contains the password hash for Hish, which is a user on the box. The other 2 users in the DB are irrelevant:

![[Pasted image 20260226184252.png]]

hashes.com reports the hash type to be bcrypt:

![[Pasted image 20260226184511.png]]

It turns out that Hish's home directory is world readable, so we can grab user.txt right there:

![[Pasted image 20260226193126.png]]

But to actually get user, let's keep going.

In his homedir, there's a **.gnupg** directory that's also world readable. This means we can read his private key(s) and use them for decryption:

![[Pasted image 20260226193724.png]]

Now we just have to find something to decrypt. Luckily, the backup folder contains a file called "keyvault.gpg".

We get a permission denied error when trying to decrypt it on the target machine, and we can't export private keys because we don't have permission to connect to the gpg agent. 

We can zip the whole directory and copy it over to our target machine though. So we'll do that and copy the keyvault.gpg file there too:

![[Pasted image 20260226195629.png]]

After unzipping, we just specify the homedir with the `--homedir <path>` option and then `-d <file>` to decrypt the file we want:

![[Pasted image 20260226200036.png]]

The password next to ENVIRONMENT.HTB (`marineSPm@ster!!`) allowed us to login as Hish via SSH. 
<br>
<br>
# **Privilege Escalation**  
Output of `sudo -l` tells us we can run a command named `systeminfo` as anybody:

![[Pasted image 20260226200454.png]]

It's a bash script according to `file`. This is what it contains:

```bash
#!/bin/bash
echo -e "\n### Displaying kernel ring buffer logs (dmesg) ###"
dmesg | tail -n 10

echo -e "\n### Checking system-wide open ports ###"
ss -antlp

echo -e "\n### Displaying information about all mounted filesystems ###"
mount | column -t

echo -e "\n### Checking system resource limits ###"
ulimit -a

echo -e "\n### Displaying loaded kernel modules ###"
lsmod | head -n 10

echo -e "\n### Checking disk usage for all filesystems ###"
df -h
```

Doesn't look like anything here can be exploited.

The sudo version appears to be 1.9.13.p3. There is a CVE associated with this version, **CVE-2023-42465**. This [advisory](https://www.openwall.com/lists/oss-security/2023/12/21/9) explains that the attack involves **fault injection** to flip the bits of a certain variable to bypass authentication. The design flaw is that this version of sudo checks whether that variable is not 0, and if so, the authentication attempt is immediately successful. The better way would be to check whether that variable is equal to a specific value, and only allow authentication if it is, otherwise deny.

**Unfortunately, that's a rabbit hole.** The complexity of this exploit is extraordinarily high and requires physical access to the server. 

___

Going back to the `sudo -l` output, there's an interesting option set called **env_keep+="ENV BASH_ENV"**. env_keep lets you specify certain environment variables to preserve when env_reset is also set (which discards all env variables except some essential ones). Here, it's preserving 2 variables, ENV and BASH_ENV. 

The last one is the interesting one, **BASH_ENV** is used for defining a path to a startup file (like .bashrc) that the shell should read before executing a non-interactive shell script (as in, no login shell is invoked). This allows an attacker to do various malicious things, like defining functions that replace real commands.

For example, in the `systeminfo` script, the `ss` command is invoked to list open ports on the machine, but we can create a function with the same name that spawns a root shell, since the script will be running as root. 

Contents of `.badprofile`:
```bash
ss() {
	bash -pi
}
```

Place it somewhere like `/dev/shm`. Now execute `sudo BASH_ENV=/dev/shm/.badprofile systeminfo`, and a root shell is returned:

![[Pasted image 20260226232707.png]]
<br>
<br>
# Skills Learned
- A common file upload technique is adding/changing a file's magic bytes to make it look like a certain kind of file when it's actually something else. This can bypass poorly designed filters and allow you to upload malicious files to the server, like webshells. Each file type has their own sequence of magic bytes.
- Intentionally causing errors on the server can sometimes output useful info like source code or web server configuration. To do this you can try removing or modifying expected parameters from requests.
- `env_keep` is an environment variable that preserves other env variables you choose when the `env_reset` option is specified. `BASH_ENV` is an env variable that dictates the shell startup file to use before running a non-interactive shell script
	- Read the WHOLE output returned by `sudo -l`, some options like these are low-hanging fruit
<br>
<br>
# Proof of Pwn
https://labs.hackthebox.com/achievement/machine/391579/659