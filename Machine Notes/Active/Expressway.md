Tags: 
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

The tool captured all we need, the encryption/hashing algorithms used, the server's identity, nonce, the server's public key, and the auth hash. Deriving the PSK should be easy from here. 

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