Tags: #Easy #Linux/Debian #ISAKMP #IKE #Weak-Hashing-Algorithms #Weak-Passwords #Password-Cracking #Outdated-software #Shared-Library-Hijacking 
# **Nmap Results**

```text
Nmap scan report for 10.10.11.87
Host is up (0.015s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.61 seconds
```
<br>
<br>

# **Service Enumeration**
This machine is a bit odd. TCP Port 22 is the only open port on the entire thing, running the latest version of OpenSSH. Let's begin enumerating there.

I ran multiple nmap scripts for SSH against the target such as ssh-auth-methods, and ssh-brute. The server accepts passwords and keypairs for authentication, but we don't have any of that.  

ssh-brute failed to find creds using the default wordlists and another wordlist of default SSH creds I found in seclists. We've hit a dead end.

I performed a UDP scan and found a service called **isakmp** listening on port 500. According to this [resource](https://trainingcamp.com/glossary/isakmp/), ISAKMP is a protocol for managing Security Associations (SAs) and cryptographic keys, and is part of the Internet Key Exchange (IKE) protocol. 

> [!info] IKE protocol
> The Internet Key Exchange (IKE) protocol facilitates secure communication over VPN connections. There are 2 phases, but the important one here is phase 1. 
> 
> Phase 1 is the **negotiation** stage where secure tunnel is created. Normally, this is done in 3 steps, each involving both peers sending data (so 6 packets total):
>    1. The peers agree on a common set of authentication methods (assume PSK for this example), encryption/hashing algorithms, and Diffie-Hellman groups 
>    2. They exchange their public keys and nonces in plaintext to derive a shared encryption key
>    3. A secure channel is created using the encryption key and they exchange their identities and a hash of the DH public keys, nonce, and PSK. If both hashes match, that proves that they both have the right PSK, and they can start talking.
> 
> IKE provides an "aggressive mode" where speed is prioritized over security. The phase is still done in 3 steps but it goes client --> server, server --> client, and finally client --> server, no round trips:
>    1. Client sends everything they need to the server for negotiation at once. This includes the DH public key, nonce, and their identity
>    2. Server sends their selected negotiation parameters, their DH public key, nonce, identity, and authentication hash
>    3. Client sends their authentication hash to prove they also know the PSK
>
>All of this happens <u>***before***</u> a secure tunnel is created, so an attacker can easily capture these packets, including the authentication hash. This can be cracked to find the PSK since the captured packets will have the other pieces of information in clear text for the attacker to just plug in.
>
>This Palo Alto [article](https://www.paloaltonetworks.com/cyberpedia/what-is-ike) explains the whole protocol very well.
<br>
<br>
# **Exploitation**
## **Initial Access**
`ike-scan` is a tool for fingerprinting servers that use the IKE protocol for VPN communication. The `-A` flag attempts to use aggressive mode for negotiation, which allows some sensitive data to be transferred in plaintext.

![[Pasted image 20260220234414.png]]

The tool retrieved all that we need, the encryption/hashing algorithms used, the server's identity, nonce, the server's public key, and the auth hash. Deriving the PSK should be easy from here. 

To actually get the data that ike-scan captured, we rerun the command with `--pskcrack`:

![[Pasted image 20260221004751.png]]

To save it to a file, set `--pskcrack=<filename>`. We can crack the PSK using the `psk-crack` tool, or by converting the output to a hash that `john` can understand with `ikescan2john`. I did the latter. 

Now using the rockyou.txt wordlist, john found the PSK to be `freakingrockstarontheroad`

![[Pasted image 20260221005823.png]]

Remember that the server's identity was `ike@expressway.htb`. I tried SSHing as ike on this domain after adding it to our /etc/hosts file, and got a shell:

![[Pasted image 20260221010157.png]]
<br>
<br>
# **Privilege Escalation**  
ike is not allowed to run any commands using sudo
There are no locally open ports with some service listening
Nothing interesting in /opt
No SUID binaries (`find / -type f -perm 6000 -ls 2>/dev/null`)

ike is part of a group named "proxy". The command `find / -group proxy` shows some files related to a program called "squid", which is a web proxy that **caches** pages for faster delivery to users so that the server doesn't have to process every request and load each page from scratch every time. 

![[Pasted image 20260221115259.png]]

The service is disabled according to `systemctl`, I've reached a dead end:

![[Pasted image 20260221115745.png]]

`linpeas` found that the machine may be vulnerable to a kernel exploit:

![[Pasted image 20260221121119.png]]

It turns out that it's actually not. The reproduction steps in the original [advisory](https://lore.kernel.org/linux-cve-announce/2025070842-CVE-2025-38236-f58c@gregkh/T/#u) did not work.

The installed sudo version is 1.9.17, which is vulnerable to **CVE-2025-32463**. In this version, when the `-R` or `--chroot` option was used, sudo would change to the specified path (that the attacker controls) before it checked the sudoers policy to see if you're even allowed to use sudo at all. 

One part of the authorization check is a system called Name Service Switch (NSS), which is configured by a file named /etc/nsswitch.conf. This file tells the computer how to retrieve information about users, groups, and hosts. 

Since sudo is already changed into the chroot directory by then, that conf file is entirely controlled by the attacker. From there, to get information about users, NSS looks at the module names written after the line starting with **passwd:** and tries them in order. For each one, it'll load the corresponding .so file to perform the check. 

This PoC on [GitHub](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/tree/main?tab=readme-ov-file) compiles an .so file that sets UID and GID to root, then runs /bin/sh

After running the POC script, we get a root shell:

![[Pasted image 20260221125828.png]]
<br>
<br>
# Skills Learned
- The IKEv1 protocol combined with using PSK as the auth method is very insecure. Better to use IKEv2 with digital signatures or asymmetric key cryptography
- Not everything that PEASS highlights in yellow is guaranteed to get you root. Still, there's a very high chance. Just don't tunnel vision if your exploit isn't working. 
<br>
<br>
# Proof of Pwn
https://labs.hackthebox.com/achievement/machine/391579/736