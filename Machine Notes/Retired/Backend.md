Tags: #Linux #Medium #Uvicorn #API #BOLA #Arbitrary-File-Read #JWT-Token-Forgery #RCE #Sensitive-Data-Exposure 
# **Nmap Results**

```text
Nmap scan report for 10.129.227.148
Host is up (0.022s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    Uvicorn
|_http-server-header: uvicorn
|_http-title: Site doesn't have a title (application/json).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Sep 28 14:16:33 2026 -- 1 IP address (1 host up) scanned in 8.60 seconds
```
<br>
<br>
# **Service Enumeration**
Preview of the web server:

![[Pasted image 20260929124415.png]]

We're looking at some kind of API. Trying to go to **/api** gives us the available endpoints:

![[Pasted image 20260929124502.png]]

**/api/v1** contains the "user" and "admin" endpoints. Going to admin gives us a 401 unauthorized response whereas the "user" endpoint gives us 404 not found for some reason. 

As feroxbuster was running in the background, it discovered **/docs**, which also throws a 401 unauthorized response. The **/openapi.json** file also appears to exist but accessing it throws a 401 as well. All of these include the `WWW-authenticate: Bearer` response header, meaning we need to include a token in our requests to pass the auth check.

**/api/v1/user/1** returns information about the admin user:

```json
{"guid":"36c2e94a-4271-4259-93bf-c96ad5948284","email":"admin@htb.local","date":null,"time_created":1649533388111,"is_superuser":true,"id":1}
```

A common thing to do when enumerating APIs is fuzzing the request type as well as the path. Fuzzing for actions in the /api/v1/user path returned a wall of 422 Unprocessable Entity responses, but sending POST requests and filtering out the paths that return 405 gives us some interesting results:

![[Pasted image 20260929141832.png]]

We now know 2 valid paths under the /api/v1/user directory, login and signup. Since we don't have any creds, we'll try signup first. A request with no data returns this:

![[Pasted image 20260929143155.png]]

It likely expects JSON data, so we'll send some with a garbage key:

![[Pasted image 20260929143814.png]]

It's expecting an email and password. After sending it, we get a 201 Created response, meaning our account was registered successfully:

![[Pasted image 20260929144105.png]]

Now we send a request to the **/api/v1/user/login** endpoint with our credentials. The server requires that we send regular form data instead of JSON,  meaning we include the `Content-Type: application/x-www-form-urlencoded` header. Also the first parameter is **username** and not **email**:

![[Pasted image 20260929144905.png]]

Great, we now have an access token we can use to look at certain resources we couldn't before. Include an authorization header with your token in all future requests like so: `Authorization: Bearer <token here>`.
<br>
<br>
# **Exploitation**
## **Initial Access**
Let's try taking a look at **/docs** again:

![[Pasted image 20261001184539.png]]

The docs helps us a lot here since we now know more about what we can do with this API.

The **/api/v1/user/updatepass** endpoint seems interesting. Maybe we can change admin's password and log in as them. Expanding the dropdown tells us what the endpoint expects:

![[Pasted image 20261001184956.png]]

We saw admin's GUID earlier when we sent a GET request to **/api/v1/user/1**, we just need to specify a password now. I'll go with `test`:

![[Pasted image 20261001185420.png]]

Seems to have worked since we can log in as admin:

![[Pasted image 20261001185814.png]]

Admin's email was also seen earlier through the same endpoint where the GUID was found. 

The docs say that to confirm we are admin, we can go to **/api/v1/admin** and see what the server says:

![[Pasted image 20261001190144.png]]

There are 2 endpoints exclusively accessible to admins, **/api/v1/admin/file** to retrieve a file, and **/api/v1/admin/exec/\<command\>** to execute commands. Attemping to execute any command results in this response:

![[Pasted image 20261001191406.png]]

We have to decode the JWT, add a "debug" parameter, and encode it back, except we'll need the JWT signing key to do so. We'll have to look around and guess filenames with the other endpoint. Let's see what's in `/proc/self/environ`:

```
APP_MODULE=app.main:app
PWD=/home/htb/uhc
LOGNAME=htb
PORT=80
HOME=/home/htb
LANG=C.UTF-8
VIRTUAL_ENV=/home/htb/uhc/.venv
INVOCATION_ID=437e7c199cf0475196417b541ae12fa2
HOST=0.0.0.0
USER=htb
SHLVL=0
PS1=(.venv) 
JOURNAL_STREAM=9:17734
PATH=/home/htb/uhc/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
OLDPWD=/
```

From this, we can infer that the user running the web app is "htb". Additionally, the `APP_MODULE` variable tells us that the python app file is located in `app/main.py`. There's not much interesting, except in the first couple of lines:

```python
import asyncio

from fastapi import FastAPI, APIRouter, Query, HTTPException, Request, Depends
from fastapi_contrib.common.responses import UJSONResponse
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

from typing import Optional, Any
from pathlib import Path
from sqlalchemy.orm import Session

from app.schemas.user import User
from app.api.v1.api import api_router
from app.core.config import settings

from app import deps
from app import crud


app = FastAPI(title="UHC API Quals", openapi_url=None, docs_url=None, redoc_url=None)
root_router = APIRouter(default_response_class=UJSONResponse)
```

The app imports some settings/config data through this line: `from app.core.config import settings`. Let's try fetching for `app/core/config.py`:

![[Pasted image 20261002134345.png]]

Here's a cleaned up version of it:

```python
from pydantic import AnyHttpUrl, BaseSettings, EmailStr, validator
from typing import List, Optional, Union

from enum import Enum


class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    JWT_SECRET: str = "SuperSecretSigningKey-HTB"
    ALGORITHM: str = "HS256"

    # 60 minutes * 24 hours * 8 days = 8 days
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8

    # BACKEND_CORS_ORIGINS is a JSON-formatted list of origins
    # e.g: '["http://localhost", "http://localhost:4200", "http://localhost:3000", \\
    # "http://localhost:8080", "http://local.dockertoolbox.tiangolo.com"]'
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    SQLALCHEMY_DATABASE_URI: Optional[str] = "sqlite:///uhc.db"
    FIRST_SUPERUSER: EmailStr = "root@ippsec.rocks"    

    class Config:
        case_sensitive = True
 

settings = Settings()
```

Towards the beginning we see the JWT secret key! Now we can use this to modify our admin JWT for the exec API endpoint. Using [jwt.io](https://jwt.io), we can verify that the key is valid and use it to forge a new token with the debug parameter. The value doesn't matter, just as long as it's present:

![[Pasted image 20261002135746.png]]

With the modified JWT, we now have command execution:

![[Pasted image 20261002135445.png]]

Start a listener, send a rev shell command, and boom:

![[Pasted image 20261002140152.png]]
<br>
<br>
## **Privilege Escalation**  
We don't have HTB's password so we can't check sudo rules. There is nothing in /opt and there aren't any ports listening locally that are out of the ordinary. HTB's home directory is empty aside from the flag and uhc directory where the API instance is located. 

The uhc directory contains a log file for all authentication attempts called `auth.log`:

```
09/30/2026, 02:39:33 - Login Success for admin@htb.local
09/30/2026, 02:42:53 - Login Success for admin@htb.local
09/30/2026, 02:56:13 - Login Success for admin@htb.local
09/30/2026, 02:59:33 - Login Success for admin@htb.local
09/30/2026, 03:04:33 - Login Success for admin@htb.local
09/30/2026, 03:07:53 - Login Success for admin@htb.local
09/30/2026, 03:21:13 - Login Success for admin@htb.local
09/30/2026, 03:29:33 - Login Success for admin@htb.local
09/30/2026, 03:31:13 - Login Success for admin@htb.local
09/30/2026, 03:37:53 - Login Success for admin@htb.local
09/30/2026, 03:46:13 - Login Failure for Tr0ub4dor&3
09/30/2026, 03:47:48 - Login Success for admin@htb.local
09/30/2026, 03:47:53 - Login Success for admin@htb.local
09/30/2026, 03:48:13 - Login Success for admin@htb.local
09/30/2026, 03:49:33 - Login Success for admin@htb.local
09/30/2026, 03:54:33 - Login Success for admin@htb.local
09/30/2026, 04:01:13 - Login Success for admin@htb.local
09/30/2026, 04:11:02 - Login Failure for test@example.com
09/30/2026, 04:13:54 - Login Failure for test@example.com
10/02/2026, 02:41:28 - Login Success for test2@example.com
10/02/2026, 02:41:38 - Login Success for test2@example.com
10/02/2026, 03:08:56 - Login Success for admin@htb.local
10/02/2026, 03:16:28 - Login Success for admin@htb.local
```

In the middle, there's a login failure for the user `Tr0ub4dor&3`, but that looks more like a password than a username. If we try executing `su` and paste the password in, we get logged in as root:

![[Pasted image 20261002141955.png]]
<br>
<br>
# Skills Learned
- Uvicorn is commonly paired together with FastAPI. Knowing what API you're dealing with can help during enumeration
- Fuzz request types along with paths when enumerating APIs
- Look closely at python app files (or any app file for that matter), specifically the imports up top. There may not always be hardcoded secrets, rather they can be brought in from other files.
- Users sometimes input their password as their username. If you can check auth logs, you may be able to get a free password for a user. 
<br>
<br>
# Proof of Pwn
https://labs.hackthebox.com/achievement/machine/391579/462