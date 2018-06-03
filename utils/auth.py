# auth.py

import uuid
import time
import datetime
import requests

from lxml import etree
from lxml.etree import Element
from lxml.etree import SubElement

from utils import sdlbodies
from utils import sdlheaders
from utils import common
from utils import ns

def old_authenticate(hostname, username, password):
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

def create_security_token_body(hostname):
    """
    Creates a structure like:

  <s:Body>
    <trust:RequestSecurityToken xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
        <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
          <wsa:Address>https://ccms.example.com/InfoShareWS/Wcf/API25/Application.svc</wsa:Address>
        </wsa:EndpointReference>
      </wsp:AppliesTo>
      <trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey</trust:KeyType>
      <trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>
    </trust:RequestSecurityToken>
  </s:Body>
    """
    body = Element("{%s}Body" % ns.s)
    requestSecurityToken = SubElement(body, "{%s}RequestSecurityToken" % ns.trust)
    appliesto = SubElement(requestSecurityToken, "{%s}AppliesTo" % ns.wsp)
    endpoint  = SubElement(appliesto,"{%s}EndpointReference" % ns.wsa)
    address   = SubElement(endpoint, "{%s}Address" % ns.wsa)
    address.text = hostname + '/InfoShareWS/Wcf/API25/Application.svc'
    keytype   = SubElement(requestSecurityToken, "{%s}KeyType" % ns.trust)
    reqtype   = SubElement(requestSecurityToken, "{%s}RequestType" % ns.trust)
    keytype.text = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey'
    reqtype.text = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue'
    return body

def create_security_token_header(hostname, username, password):
    """
    Creates a structure like:

  <s:Header>
    :GenericHeaders     via create_generic_headers()
    <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
      :TimeStamp        via create_timestamp()
      :UsernameToken    via create_usernametoken()
    </o:Security>
  </s:Header>
    """
    action_s = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue'
    to_s     = hostname + '/InfoShareSTS/issue/wstrust/mixed/username'

    header = Element("{%s}Header" % ns.s, nsmap = { 's':ns.s })
    action, messageid, replyto, to = sdlheaders.create_generic_headers(action_s, to_s)
    header.append(action)
    header.append(messageid)
    header.append(replyto)
    header.append(to)
	
    security = SubElement(header, "{%s}Security" % ns.o, nsmap = {'o':ns.o})
    security.attrib["{%s}mustUnderstand" % ns.s] = '1'
    timestamp = sdlheaders.create_timestamp()
    usernametoken = sdlheaders.create_usernametoken(username, password)
    security.append(timestamp)
    security.append(usernametoken)

    header.append(security)

    return header

def get_security_token(hostname, username, password):
    soapheader = create_security_token_header(hostname, username, password)
    soapbody   = create_security_token_body(hostname) 
    soapenv    = common.create_envelope(soapheader, soapbody)
    return soapenv

def send_security_token(hostname, soapenv):
    http_headers = {'Accept-Encoding':'gzip, deflate', 'Content-Type':'application/soap+xml; charset=utf-8' }
    url = hostname + '/InfoShareSTS/issue/wstrust/mixed/username'
    r = requests.post(url, headers=http_headers, data=soapenv)
    if r.status_code != 200:
        raise SystemExit("Error %i: %s\nFull message: %s" % (r.status_code, r.reason, r.text))
    return r
