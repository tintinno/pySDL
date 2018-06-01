# 

import time
import datetime
import uuid
from lxml.etree import Element
from lxml.etree import SubElement
from utils import ns

def create_generic_headers(action_s, to_s):
    """
    Creates a structure like:

    <a:Action s:mustUnderstand="1">SOME ACTION URI</a:Action>
    <a:MessageID>urn:uuid:971be013-6eec-4cfc-9395-f9c69fe52fc1</a:MessageID>
    <a:ReplyTo>
        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand="1">SOME DESTINATION URI</a:To>
    """
    local_nsmap = {'a':ns.a, 's':ns.s}
    action = Element("{%s}Action" % ns.a, nsmap = local_nsmap)
    action.attrib["{%s}mustUnderstand" % ns.s] = '1'
    action.text = action_s

    messageid = Element("{%s}MessageID" % ns.a, nsmap = local_nsmap)
    messageid.text = 'urn:uuid:' + str(uuid.uuid4())

    replyto = Element("{%s}ReplyTo" % ns.a, nsmap = local_nsmap)
    address = SubElement(replyto, "{%s}Address" % ns.a)
    address.text = 'http://www.w3.org/2005/08/addressing/anonymous'

    to = Element("{%s}To" % ns.a, nsmap = local_nsmap)
    to.attrib["{%s}mustUnderstand" % ns.s] = '1'
    to.text = to_s

    return action, messageid, replyto, to

def create_timestamp():
    """
    Creates a structure like:

    <u:Timestamp u:Id="_0">
        <u:Created>2018-05-31T19:55:24.123Z</u:Created>
        <u:Expires>2018-05-31T20:00:24.123Z</u:Expires>
    </u:Timestamp>
    """
    # the created and expires values need to be in UTC
    offset    = time.gmtime().tm_hour - time.localtime().tm_hour
    now       = datetime.datetime.now()
    now       = now + datetime.timedelta(hours=offset)                          # hour offset
    created_s = now.strftime('%Y-%m-%dT%H:%M:%S.123Z')
    expires_s = (now + datetime.timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%S.123Z')
    
    local_nsmap = { 'u': ns.u }
    timestamp = Element("{%s}Timestamp" % ns.u, nsmap = local_nsmap)
    timestamp.attrib['{%s}Id' % ns.u] = '_0'
    created = SubElement(timestamp, "{%s}Created" % ns.u)
    expires = SubElement(timestamp, "{%s}Expires" % ns.u)
    created.text = created_s
    expires.text = expires_s
    return timestamp

# see authenticate() for this structure
def create_usernametoken(username_s, password_s):
    """
    Creates a structure like:

    <o:UsernameToken u:Id="uuid-cd57caa2-edc2-4bc2-9bcb-10a8a07e970c-1">
        <o:Username></o:Username>
        <o:Password Type="..."></o:Password>
    </o:UsernameToken>
    """
    type_s = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText'
    local_nsmap = { 'o': ns.o, 'u':ns.u }
    usernametoken = Element("{%s}UsernameToken" % ns.o, nsmap = local_nsmap)
    usernametoken.attrib["{%s}Id" % ns.u] = 'uuid-' + str(uuid.uuid4()) + '-1'
    username = SubElement(usernametoken, "{%s}Username" % ns.o)
    password = SubElement(usernametoken, "{%s}Password" % ns.o)
    password.attrib['Type'] = type_s
    username.text = username_s
    password.text = password_s

    return usernametoken

def create_security_header(encryptedData):
    """
    Creates a structure like:

    <o:Security s:mustUnderstand="1">
      :Timestamp        via create_timestamp()
      :EncryptedData    returned via authenticate()
      :Signature        <needs research>
    </o:Security>
    """
    local_nsmap = { 'o': ns.o, 's':ns.s }
    security = Element("{%s}Security" % ns.o, nsmap = local_nsmap)
    security.attrib["{%s}mustUnderstand" % ns.s] = '1'
    t = create_timestamp()
    security.append(t)

    return security

