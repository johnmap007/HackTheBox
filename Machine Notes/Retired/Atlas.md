Tags: #Hard #Windows #Spring-Boot #FTP #FTP-Anonymous-Login #Source-Code-Analysis #Java 
# **Nmap Results**

```text
Nmap scan report for 10.129.12.28
Host is up (0.021s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           FileZilla ftpd 1.7.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -r--r--r-- 1 ftp ftp        22851463 Jul 03  2023 atlas-pilot-1.0.0-SNAPSHOT.jar
|_-r--r--r-- 1 ftp ftp          586379 Jul 03  2023 atlas_generator.zip
|_ssl-date: TLS randomness does not represent time
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla.
| ssl-cert: Subject: commonName=filezilla-server self signed certificate
| Not valid before: 2023-06-30T15:35:45
|_Not valid after:  2024-06-30T15:40:45
| tls-alpn: 
|_  ftp
22/tcp   open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=ATLAS
| Not valid before: 2026-03-28T20:07:17
|_Not valid after:  2026-09-27T20:07:17
|_ssl-date: 2026-03-30T00:21:35+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: ATLAS
|   NetBIOS_Domain_Name: ATLAS
|   NetBIOS_Computer_Name: ATLAS
|   DNS_Domain_Name: ATLAS
|   DNS_Computer_Name: ATLAS
|   Product_Version: 10.0.19041
|_  System_Time: 2026-03-30T00:21:30+00:00
8080/tcp open  http          Apache Tomcat (language: en)
|_http-title: Site doesn't have a title (text/html;charset=UTF-8).
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.74 seconds
```
<br>
<br>
# **Service Enumeration**

First thing to look at should be the FTP server and grab what we can, given that anonymous login is allowed. There are 2 things, a java JAR app and a zip file:

![[Pasted image 20260329203700.png]]

I downloaded both to my machine and took a look at them. When executing the JAR file, a web server opened on port 8080. This is what's displayed:

![[Pasted image 20260329211133.png]]

I also unzipped the zip file and found files and folders that looked like a Java project. It must be the source code for this app. 

The earlier nmap scan also found a web server on port 8080, which ended up displaying the same thing as above. We should take a look at that source code now.

In **FileUploadController.java**, the `handleFileUpload()` method is what gets called first when a user visits the site:

```java
@PostMapping("/")
public String handleFileUpload(@RequestParam("file") MultipartFile file,
		RedirectAttributes redirectAttributes, Model model) {

	try {
		Employee person = Client.parseXML(file.getInputStream());
		model.addAttribute("name", person.getName());
		model.addAttribute("id", person.getId());
		model.addAttribute("email", person.getEmail());
		model.addAttribute("phone", person.getPhone());
		model.addAttribute("profile", person.getProfile());
		model.addAttribute("title", person.getTitle());
		model.addAttribute("skills", person.getSkills());
		model.addAttribute("educationTitle", person.getEducationTitle());
		model.addAttribute("educationText", person.getEducationText());
		model.addAttribute("talentTitle1", person.getTalentTitles()[0]);
		model.addAttribute("talentTitle2", person.getTalentTitles()[1]);
		model.addAttribute("talentTitle3", person.getTalentTitles()[2]);
		model.addAttribute("talentText1", person.getTalentTextes()[0]);
		model.addAttribute("talentText2", person.getTalentTextes()[1]);
		model.addAttribute("talentText3", person.getTalentTextes()[2]);		
		model.addAttribute("message", person.getMessage());

	} catch (Exception e) {
		e.printStackTrace();
	}

	return "srt-resume";
}
```

There's a call to `parseXML()` in the try block, which is located in **Client.java**:

```java
public static Employee parseXML(InputStream uploadFile) throws IOException{
	
	try {
	
	
		Reader targetReader = new InputStreamReader(uploadFile);
		Unmarshaller unmarshaller = new Unmarshaller(Employee.class);
		Employee employee = (Employee)unmarshaller.unmarshal(targetReader);
	
	
		System.out.println("XML Unmarschall Sucessfully");
		System.out.println(employee.getName());
		System.out.println(employee.getId());
		System.out.println(employee.getEducationText());
	
		employee.setMessage("Parsing Successfull");
		
		return employee;
	
	 } catch (Exception e) {
		e.printStackTrace();
	
		Employee employee = new Employee();
		employee.setMessage(e.toString());
	
		return employee;
	
	 }
	
	}
```

These lines are of interest to us:

```java
Reader targetReader = new InputStreamReader(uploadFile);
Unmarshaller unmarshaller = new Unmarshaller(Employee.class);
Employee employee = (Employee)unmarshaller.unmarshal(targetReader);
```

If you look at the earlier image of the website, you see that it allows the user to upload an XML file containing "Employee data". That file is passed as an argument to `parseXML()`, as you can see in `handleFileUpload()`. 

Here, we have an Employee class that is instantiated by deserializing whatever's in that file, which is completely controlled by the user. This is known as **insecure deserialization**. 
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