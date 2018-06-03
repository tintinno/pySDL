# sdlbodies.py

import uuid
from lxml.etree import Element
from lxml.etree import SubElement
from utils import ns

def create_requestSecurityToken(binarySecret):
    """
    Creates a structure like:

    <trust:RequestSecurityToken xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <trust:TokenType>http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/sct</trust:TokenType>
      <trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>
      <trust:Entropy>
        <trust:BinarySecret 
             u:Id="uuid-f535f86f-6037-4890-890b-75c0f506675d-1" 
             Type="http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce">
                SOME BINARY SECRET
        </trust:BinarySecret>
      </trust:Entropy>
      <trust:KeySize>256</trust:KeySize>
    </trust:RequestSecurityToken>
    """
    local_nsmap  = {'trust':ns.trust}
    tokenType_s  = 'http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/sct'
    reqType_s    = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue'
    binSecType_s = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce'

    reqSecToken = Element("{%s}RequestSecurityToken" % ns.trust, nsmap = local_nsmap)
    tokenType   = SubElement(reqSecToken, "{%s}TokenType" % ns.trust)
    tokenType.text = tokenType_s

    requestType = SubElement(reqSecToken, "{%s}RequestType" % ns.trust)
    requestType.text = reqType_s

    entropy     = SubElement(reqSecToken, "{%s}Entropy" % ns.trust)
    binarySec   = SubElement(entropy, "{%s}BinarySecret" % ns.trust)
    binarySec.attrib["{%s}Id" % ns.u] = 'uuid-' + str(uuid.uuid4()) + '-1'
    binarySec.attrib["Type"] = binSecType_s
    keysize     = SubElement(reqSecToken, "{%s}KeySize" % ns.trust)
    keysize.text = '256'

    return reqSecToken

def create_intial_auth_body(hostname):
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

