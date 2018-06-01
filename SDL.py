# SDL.py

import uuid
import time
import datetime
import requests
from lxml import etree

def authenticate(hostname, username, password):
    # set the HTTP headers
    headers = {	'Accept-Encoding':'gzip, deflate', 'Content-Type':'application/soap+xml; charset=utf-8' }

    # get the values needed for the SOAP envelope.
    dest_url  = hostname + '/InfoShareSTS/issue/wstrust/mixed/username'
    appl_url  = hostname + '/InfoShareWS/Wcf/API25/Application.svc'
    messageid = 'urn:uuid:' + str(uuid.uuid4())
    untoken   = 'uuid-' + str(uuid.uuid4()) + '-1'

    # the created and expires values need to be in UTC
    offset    = time.gmtime().tm_hour - time.localtime().tm_hour
    now       = datetime.datetime.now()
    now       = now + datetime.timedelta(hours=offset)				# hour offset
    created   = now.strftime('%Y-%m-%dT%H:%M:%S.123Z')
    expires   = (now + datetime.timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%S.123Z')

    # set the appropriate values in the SOAP message
    auth = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><s:Header><a:Action s:mustUnderstand="1">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action><a:MessageID>%s</a:MessageID><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand="1">%s</a:To><o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><u:Timestamp u:Id="_0"><u:Created>%s</u:Created><u:Expires>%s</u:Expires></u:Timestamp><o:UsernameToken u:Id="%s"><o:Username>%s</o:Username><o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">%s</o:Password></o:UsernameToken></o:Security></s:Header><s:Body><trust:RequestSecurityToken xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>%s</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey</trust:KeyType><trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType></trust:RequestSecurityToken></s:Body></s:Envelope>""" % (
        messageid,
        dest_url,
        created,
        expires,
        untoken,
        username,
        password,
        appl_url
    )

    r = requests.post(dest_url, headers=headers, data=auth)

    if r.status_code != 200:
        print('Error %i: %s' % (r.status_code, r.reason))

    return r

class SDL(object):
    def __init__(self, hostname):
        self.hostname = hostname
    
    def login(self, username, password):
        r = authenticate(self.hostname, username, password)
        
        # to demonstrate the login was successfull, write the <EncryptedData> to file
        tree = etree.fromstring(r.text)
        enc = tree.xpath("//*[namespace-uri() = 'http://www.w3.org/2001/04/xmlenc#']")[0]
        encs = etree.tostring(enc).decode('utf-8')
        with open('encs.xml','w') as out:
            out.write(encs)
