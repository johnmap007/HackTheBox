The Windows firewall usually blocks pings, so when running nmap and the host seems down, use -Pn

SMB is a good place to start enumerating if found (port 445). 
- `smbclient` is how you interact with this service
- `netexec` is a very popular tool for testing

In nmap, the commonName is the hostname of the AD machine. Add it to /etc/hosts if you see one

Always check for **null authentication**, if you can access any resource without authenticating.
- Example: `nxc smb retro.vl -u '' -p '' --users` --> return a list of users on the machine
Also try authenticating with the "Guest" account, which is almost always on Windows machines.

Every Windows account has a **security ID (SID)** assigned to it upon creation. The SID ends in a relative identifier, or an RID. 
An **RID brute force attack** is an enumeration technique to discover users on the box. 
- netexec can do this easily: `nxc smb retro.vl -u 'Guest' -p '' --rid-brute`
- Also can be done with rpcclient: `rpcclient retro.vl -U 'guest'`, run `lsaquery` to obtain SID, then `lookupsids <SID>`

Password spraying with nxc:
- `nxc smb retro.vl -u 'trainee' -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding`

Everytime you come across a new set of credentials, you have to **reenumerate everything again (e.g --users and --shares).** Accounts can have different ACLs, privileges, and other things.

In the example machine "retro", the "trainee" account has read access to all shares and can list users unlike the "Guest" account

The password for a pre windows 2000s computer account is the name of the account without the '$' in all lowercase. To log in to the account, the password must be changed first, which can be achieved with `impacket-changepasswd`

`certipy-ad`: For enumerating CA servers. netexec can of course do this too

An ESC1 vulnerability allows you to request a certificate for another user that can be used to authenticate to the domain as them