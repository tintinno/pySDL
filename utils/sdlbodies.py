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
