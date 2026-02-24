Tags: #Linux #Medium #Nginx #Argument-Injection 
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

There's a PoC in this [GitHub](https://github.com/joaovicdev/EXPLOIT-CVE-2025-27515) repo that automates the whole process.

NOTE: Exploit doesn't work out of the box. It fails when trying to get CSRF token. Try tweaking it in VSCode
- Only POST requests are allowed and you need to match parameters. 
- Upload a random profile photo, intercept request with burpsuite, check what those params are and put them in the script
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