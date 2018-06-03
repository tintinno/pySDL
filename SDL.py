# SDL.py

import requests
from lxml import etree
from utils import sdlheaders
from utils import sdlbodies
from utils import auth

class SDL(object):
    def __init__(self, hostname):
        self.hostname = hostname
   
	# ultimately, login() should complete the entire round of authentication  
    def login(self, username, password):
        soapenv = auth.get_security_token(self.hostname, username, password)
        r = auth.send_security_token(self.hostname, soapenv)

        # to demonstrate the login was successfull, write the <EncryptedData> to file
        tree = etree.fromstring(r.text)
        enc = tree.xpath("//*[namespace-uri() = 'http://www.w3.org/2001/04/xmlenc#']")[0]
        encs = etree.tostring(enc).decode('utf-8')
        with open('encs.xml','w') as out:
            out.write(encs)
