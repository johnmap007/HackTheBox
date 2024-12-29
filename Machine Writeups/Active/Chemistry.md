Tags: 
# **Nmap Results**

```text
Nmap scan report for 10.10.11.38
Host is up (0.087s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Sun, 29 Dec 2024 15:42:35 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=12/29%Time=67716DE9%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3
SF:\x20Python/3\.9\.5\r\nDate:\x20Sun,\x2029\x20Dec\x202024\x2015:42:35\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20
SF:html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=
SF:\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"wid
SF:th=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemi
SF:stry\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\
SF:x20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20\n\x
SF:20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class
SF:=\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"title\"
SF:>Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>
SF:Welcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x20tool\
SF:x20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographic\x20I
SF:nformation\x20File\)\x20and\x20analyze\x20the\x20structural\x20data\x20
SF:contained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<center
SF:><a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"btn\">R
SF:egister</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\
SF:x20\x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUB
SF:LIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x
SF:20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Con
SF:tent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>
SF:\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20
SF:response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400
SF:</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20
SF:version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Er
SF:ror\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20r
SF:equest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20
SF:</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
```
<br>
<br>

# **Service Enumeration**
Nmap results found a Python Werkzeug web server on port 5000


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

## **Post-Exploit Enumeration**
### **Operating Environment**

> [!tldr]- OS &amp; Kernel
>Document here:
>- Windows
>    - `systeminfo` or `Get-ComputerInfo` output
>    - Check environment variables:
 >       - CMD: `set`
 >       - PowerShell: `Get-ChildItem Env:\`
>
>- *nix
>    - `uname -a` output
>    - `cat /etc/os-release` (or similar) output
>    - Check environment variables:
>       - `env` or `set`

> [!tldr]- Current User
> Document here:
> - Windows
>     - `whoami /all` output
>   
> - *nix
>     - `id` output
>     - `sudo -l` output

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

> [!tldr]- Domain Users (Standalone Domain Controller or Network)
> Document here any interesting username(s) after running the below commands:
> - Windows
>     - `net user /domain` or `Get-ADUser -Filter * -Properties *` output
>     - `net user <username> /domain` or `Get-ADUser -Identity <username> -Properties *` to enumerate details about specific domain users
>     - Not a local administrator and can't run PowerShell AD cmdlets?
>       - See here: https://notes.benheater.com/books/active-directory/page/powershell-ad-module-on-any-domain-host-as-any-user
>     - Can you dump and pass/crack local user / admin hashes from the SAM using your current access?
>     - Can you dump and pass/crack hashes from LSA using your current access?
> 
> - *nix
>     - Check if joined to a domain
>       - /usr/sbin/realm list -a
>       - /usr/sbin/adcli info <realm_domain_name>
> 
>     - No credential:
> 
>       - Check for log entries containing possible usernames
> 
>         - `find /var/log -type f -readable -exec grep -ail '<realm_domain_name>' {} \; 2>/dev/null`
>         - Then, grep through each log file and remove any garbage from potential binary files:
> 
>           - Using strings: `strings /var/log/filename | grep -i '<realm_domain_name>'`
>           - If strings not available, try using od: `od -An -S 1 /var/log/filename | grep -i '<realm_domain_name>'`
>           - If od not available, try grep standalone: `grep -iao '.*<realm_domain_name>.*' /var/log/filename`
> 
>         - Validate findings:
>           - Check if discovered usernames are valid: `getent passwd <domain_username>`
>           - If valid, check user group memberships: List `id <domain_username>`
>         - Check domain password and lockout policy for password spray feasibility
> 
>       - See `Domain Groups`, as certain commands there can reveal some additional usernames
> 
>      - With a domain credential:
> 
>        - If you have a valid domain user credential, you can try `ldapsearch`
>        - Dump all objects from LDAP: `ldapsearch -x -H ldap://dc-ip-here -D 'CN=username,DC=realmDomain,DC=realmTLD' -W -b 'DC=realmDomain,DC=realmTLD' 'objectClass=*'`
>        - Dump all users from LDAP: `ldapsearch -x -H ldap://dc-ip-here -D 'CN=username,DC=realmDomain,DC=realmTLD' -W -b 'DC=realmDomain,DC=realmTLD' 'objectClass=account'`
> 
> 
>     - If you're root on the domain-joined host:
> 
>        - You can try best-effort dumping the SSSD cache:
> 
>          - Using strings: `strings /var/lib/sss/db/cache_<realm_domain_name>.ldb | grep -iE '[ou|cn]=.*user.*'` | grep -iv 'disabled' | sort -u
>          - If strings not available, try using od: `od -An -S 1 /var/lib/sss/db/cache_<realm_domain_name>.ldb | grep -iE '[ou|cn]=.*user.*'` | grep -iv 'disabled' | sort -u
>          - If od not available, try grep standalone: `grep -iao '.*<realm_domain_name>.*' /var/lib/sss/db/cache_<realm_domain_name>.ldb | sed 's/[^[:print:]\r\t]/\n/g' | grep -iE '[ou|cn]=.*user.*' | grep -iv disabled`
> 
>        - You can transfer the SSSD TDB cache for local parsing
> 
>          - Default file path: /var/lib/sss/db/cache_<realm_domain_name>.tdb
>          - You can dump this file with tools such as `tdbtool` or `tdbdump`

> [!tldr]- Domain Groups (Standalone Domain Controller or Network)
> Document here any interesting group(s) after running the below commands:
> - Windows
>     - `net group /domain` or `Get-ADGroup -Filter * -Properties *` output
>     - `net group <group_name> /domain` or `Get-ADGroup -Identity <group_name> | Get-ADGroupMember -Recursive` to enumerate members of specific domain groups
>     - Not a local administrator and can't run PowerShell AD cmdlets?
>       - See here: https://notes.benheater.com/books/active-directory/page/powershell-ad-module-on-any-domain-host-as-any-user
> 
> - *nix
> 
>     - Check if joined to a domain
>       - /usr/sbin/realm list -a
>       - /usr/sbin/adcli info <realm_domain_name>
> 
>     - No credential:
> 
>       - Enumerate default Active Directory security groups: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#default-active-directory-security-groups
> 
>         - `getent group 'Domain Admins@<realm_domain_name>'`
>         - `getent group 'Domain Users@<realm_domain_name>'`
>         - NOTE: `getent` will only return domain group members that have been cached on the local system, not all group members in the domain
>         - This can still build a substantial user list for password spraying (check domain password and lockout policy)
> 
>     - With a domain credential:
> 
>        - If you have a valid domain user credential, you can try `ldapsearch`
>        - Dump all objects from LDAP: `ldapsearch -x -H ldap://dc-ip-here -D 'CN=username,DC=realmDomain,DC=realmTLD' -W -b 'DC=realmDomain,DC=realmTLD' 'objectClass=*'`
>        - Dump all groups from LDAP: `ldapsearch -x -H ldap://dc-ip-here -D 'CN=username,DC=realmDomain,DC=realmTLD' -W -b 'DC=realmDomain,DC=realmTLD' 'objectClass=group'`
> 
>     - If you're root on the domain-joined host:
> 
>        - You can try dumping the SSSD cache:
> 
>          - Using strings: `strings /var/lib/sss/db/cache_<realm_domain_name>.ldb | grep -i '<realm_domain_name>'`
>          - If strings not available, try using od: `od -An -S 1 /var/lib/sss/db/cache_<realm_domain_name>.ldb | grep -i '<realm_domain_name>'`
>          - If od not available, try grep standalone: `grep -iao '.*<realm_domain_name>.*' /var/lib/sss/db/cache_<realm_domain_name>.ldb | sed 's/[^[:print:]\r\t]/\n/g' | grep -iE '[ou|cn]=.*group.*' | grep -i '^CN='`
> 
>        - You can transfer the SSSD TDB cache for local parsing
> 
>          - Default file path: /var/lib/sss/db/cache_<realm_domain_name>.tdb
>          - You can dump this file with tools such as `tdbtool` or `tdbdump`

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

> [!tldr]- ARP Table
>
> If targeting a network and enumerating additional hosts...
> Document here:
>
> - Windows
>     - `arp -a` or `Get-NetNeighbor` output
> - *nix
>     - `ip neigh` or `arp -a` output

> [!tldr]- Routes
>
> If targeting a network and enumerating additional hosts...
> Document here:
>
> - Windows
>     - `route print` or `Get-NetRoute` output
> - *nix
>     - `ip route` or `route` output

> [!tldr]- Ping Sweep
>
> If the host has access to additional routes / interfaces:
>
>- Look at the IP address space and network mask
>- Find a ping sweep script that will work for the target network
>- Or you could try:
>	- Transfering `nmap` or some other host discover tool to the host
>	- Set up a SOCKS proxy and try a port scan through the foothold

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

> [!tldr]- /opt/interesting_dir/interesting-file2.txt
>
> Add full file contents
> Or snippet of file contents

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