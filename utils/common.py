from lxml import etree
from lxml.etree import Element
from utils import ns

def create_envelope(soapheader, soapbody):
    env = Element("{%s}Envelope" % ns.s, nsmap = {'s':ns.s, 'a':ns.a, 'u':ns.u})
    env.append(soapheader)
    env.append(soapbody)
    env = etree.tostring(env)
    return env
