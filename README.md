# pySDL
A Python client for SDL LiveContent

This repository is only dreaming about a MVP. You've been warned.

## Long Term Goal

A complete Python client for SDL LiveContent run from Linux!

## Immediate Goal

Authenticate to the Application.svc endpoint and run GetVersion().

If you run `python3 login.py`, you'll see an encs.xml file that contains the EncryptedData of the response.

## Use

Authentication credentials are stored in a `.netrc` file. 
[More info](https://www.gnu.org/software/inetutils/manual/html_node/The-_002enetrc-file.html).

The `account` value in the .netrc file is used as the hostname.

```
$ cat ~/.netrc
machine SDL
login myUserName
account https://ccms.example.com
password superSecretPassword
$
```
Don't forget to run `chmod 600 ~/.netrc` after creating the file.
