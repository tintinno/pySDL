# pySDL
A Python client for SDL LiveContent

This repository is only dreaming about a MVP. You've been warned.

## Long Term Goal

A complete Python client for SDL LiveContent run from Linux!

## Immediate Goal

Authenticate to the Application.svc endpoint and run GetVersion(). 

## Authentication

Authentication requires a multi-message exchange, the first part of which is complete. Run `python3 login.py` and the EncryptedData of the response will be written to the file `encs.xml`.

## User Credentials

Authentication credentials are stored in a
[.netrc](https://www.gnu.org/software/inetutils/manual/html_node/The-_002enetrc-file.html)
file.

The `account` value in the `.netrc` file is used as the hostname. The 
first line must be `machine SDL`.

```
$ cat ~/.netrc
machine SDL
login myUserName
account https://ccms.example.com
password superSecretPassword
$
```
Set file permissions with `chmod 600 ~/.netrc`.
