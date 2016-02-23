#!/usr/bin/env python
# RDPy
#
# Copyright (C) 2013 Jeffrey Stiles (@uth_cr33p)(jeff@aerissecure.com)
#
# Todo:
#   - switch to asn1tinydecoder.py: http://getreu.net/public/downloads/software/ASN1_decoder/README.html
#
# Thank you to:
# http://labs.portcullis.co.uk/application/rdp-sec-check/
# http://troels.arvin.dk/code/nagios/check_x224
#
# RDP Protocol Data Unit (PDU) Secifications
# see PDF document: http://tinyurl.com/mefmmo9
#
# COMPLETE X.224 INFORMATION
#
# x224ConnectionRequestPDU
# |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|
# |                          tpktHeader                           |
# |                           x224Crq                             |
# |                      ...                      |  rdpNegData   |
# |                             ...                               |
# |                      ...                      |               |
# | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |
# tpktHeader (4 bytes): TPKT Header
#   big endian(>):
#   version(B)
#   reserved(B)
#   length(H)
# x224Crq (7 bytes): Connection Request Transport Protocol Data Unit
#   big endian(>):
#   length(B)
#   cr - connection request code(B)
#   dst-ref(H)
#   src-ref(H)
#   co - class option(B)
# rdpNegData(RDP_NEG_REQ) (8 bytes):
#   little endian(<):
#   type(B)
#   flags(B)
#   length(H)
#   rp - requestedProtocols(I)
#
# x224ConnectionConfirmPDU
# |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|
# |                          tpktHeader                           |
# |                           x224Ccf                             |
# |                      ...                      | routingToken  |
# |                             ...                               |
# |                           cookie                              |
# |                             ...                               |
# |                          rdpNegData                           |
# |                             ...                               |
# | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |
# tpktHeader (4 bytes): TPKT Header
#   big endian(>):
#   version(B)
#   reserved(B)
#   length(H)
# x224Ccf (7 bytes): Connection Confirm Transport Protocol Data Unit
#   big endian(>):
#   length(B)
#   cc - connection confirm code(B)
#   dst-ref(H)
#   src-ref(H)
#   co - class option(B)
# routingToken (optional)
# cookie (optional)
# rdpNegData(RDP_NEG_RSP) (8 bytes):
#   little endian(<):
#   type(B)
#   flags(B)
#   length(H)
#   sp - selectedProtocol(I)
# rdpNegData(RDP_NEG_FAILURE) (8 bytes):
#   little endian(<):
#   type(B)
#   flags(B)
#   length(H)
#   fc - failureCode(I)
#
# INCOMPLETE MCS INFORMATION
#
# 2.2.1.3 (p.38)
# MCSConnectIntialPDU
# |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|
# |                          tpktHeader                           |
# |                           x224data            |    mcsCi      |
# |                             ...                               |
# ... etc
#
#
# 2.2.1.4 (p.55)
# MCSConnectResposePDU
# |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|
# |                          tpktHeader                           |
# |                           x224data            |   mcsCrsp     |
# |                             ...                               |
# ... etc
# tpktHeader (4 bytes)
# x224Data (3 bytes)
# mcsCrsp (variable)(BER)
# gccCCrsp (variable)(PER)
# serverCoreData(TS_UD_SC_COR) (12 bytes)
#   header(HH), type(H)(\x0c\x02), length(H)(..)
#   version(I)
#   clientRequestedProtocols(I)
#   earlyCapabilityFlags(I)
# serverNetworkData (variable)
# serverSecurityData (variable)
#   header(HH), type(H)(\x02\x0c), length(H)(..)
#   encryptionMethod(I)
#   encryptionLevel(I)
#   serverRandomLen(I)
#   serverCertLen(I)
#   ...
# serverMessageChannelData (8 bytes)
# serverMultitransportChannelData (8 bytes)

import argparse
import socket
import struct
import time
import re
from pyasn1.codec.ber import decoder

# custom errors
class ConnectionError(Exception):
    """Generic connection error"""
    pass

class ResponseError(Exception):
    """Generic response error"""
    pass


# protocols
PROTOCOL_OLD = -1           # Old RDP Protocol (Win XP/2000/2003)
PROTOCOL_RDP = 0            # Standard RDP security
PROTOCOL_SSL = 1            # TLS
PROTOCOL_HYBRID = 2         # CredSSP (requires PROTOCOL_SSL (3))
PROTOCOL_SSL_HYBRID = 3         # PROTOCOL_SSL + PROTOCOL_HYBRID
PROTOCOL_HYBRID_EX = 8          # CredSSP EX (requires PROTOCOL_HYBRID (10))
PROTOCOL_HYBRID_HYBRID_EX = 10  # PROTOCOL_HYBRID + PROTOCOL_HYBRID_EX
# 10 FOR PROTOCOL_HYBRID_EX (requires PROTOCOL_HYBRID)
# 3 FOR PROTOCOL_HYBRID (requires PROTOCOL_SSL)
LU_PROTOCOL = {
    PROTOCOL_OLD: 'rdpNegData ignored (Windows 2000/XP/2003?)', # rdpNegData supplied but returned empty
    PROTOCOL_RDP: 'Standard RDP Security',
    PROTOCOL_SSL: 'TLS 1.0, 1.1 or 1.2 Security',
    PROTOCOL_HYBRID: 'Hybrid (TLS + CredSSP) Security',
    PROTOCOL_SSL_HYBRID: 'Hybrid (TLS + CredSSP) Security',
    PROTOCOL_HYBRID_EX: 'Hybrid (TLS + CredSSP EX) Security',
    PROTOCOL_HYBRID_HYBRID_EX: 'Hybrid (TLS + CredSSP EX) Security',
}

# negotiation codes
RDP_NEG_TYPE_REQ = 1        # Code for request
RDP_NEG_TYPE_RSP = 2        # Code for response
RDP_NEG_TYPE_FAILURE = 3    # Code for response failure
NEG_TYPE = {
    RDP_NEG_TYPE_REQ: 'RDP Negotiation Request',
    RDP_NEG_TYPE_RSP: 'RDP Negotiation Response',
    RDP_NEG_TYPE_FAILURE: 'RDP Negotiation Failure',
}

# failure codes
SSL_REQUIRED_BY_SERVER = 1
SSL_NOT_ALLOWED_BY_SERVER = 2
SSL_CERT_NOT_ON_SERVER = 3
INCONSISTENT_FLAGS = 4
HYBRID_REQUIRED_BY_SERVER = 5
SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 6
LU_FAILURE_CODE = {
    SSL_REQUIRED_BY_SERVER: 'SSL REQUIRED BY SERVER',
    SSL_NOT_ALLOWED_BY_SERVER: 'SSL NOT ALLOWED BY SERVER',
    SSL_CERT_NOT_ON_SERVER: 'SSL CERT NOT ON SERVER',
    INCONSISTENT_FLAGS: 'INCONSISTENT FLAGS',
    HYBRID_REQUIRED_BY_SERVER: 'HYBRID REQUIRED BY SERVER',
    SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER: 'SSL WITH USER AUTH REQUIRED BY SERVER',
}

# encryption levels
ENCRYPTION_LEVEL_NONE = 0
ENCRYPTION_LEVEL_LOW = 1
ENCRYPTION_LEVEL_CLIENT_COMPATIBLE = 2
ENCRYPTION_LEVEL_HIGH = 3
ENCRYPTION_LEVEL_FIPS = 4
LU_ENCRYPTION_LEVEL = {
    ENCRYPTION_LEVEL_NONE: 'None',
    ENCRYPTION_LEVEL_LOW: 'Low',
    ENCRYPTION_LEVEL_CLIENT_COMPATIBLE: 'Client Compatible',
    ENCRYPTION_LEVEL_HIGH: 'High',
    ENCRYPTION_LEVEL_FIPS: 'FIPS',

}

# encryption methods
ENCRYPTION_METHOD_NONE = 0
ENCRYPTION_METHOD_40BIT = 1
ENCRYPTION_METHOD_128BIT = 2
ENCRYPTION_METHOD_56BIT = 8
ENCRYPTION_METHOD_FIPS = 10
LU_ENCRYPTION_METHOD = {
    ENCRYPTION_METHOD_NONE: 'None',
    ENCRYPTION_METHOD_40BIT: '40 Bit',
    ENCRYPTION_METHOD_128BIT: '128 Bit',
    ENCRYPTION_METHOD_56BIT: '56 Bit',
    ENCRYPTION_METHOD_FIPS: 'FIPS',
}

# server versions
SERVER_VERSION_4 = 524289 # 0x00080001
SERVER_VERSION_5 = 524292 # 0x00080004
LU_SERVER_VERSION = {
    SERVER_VERSION_4: 'RDP 4.0 servers',
    SERVER_VERSION_5: 'RDP 5.0, 5.1, 5.2, 6.0, 6.1, 7.0, 7.1, and 8.0 servers',
}

# Denial of Service (DoS), Man-in-the-Middle (MitM), Weak Encryption
# configuration issues
NLA_SUPPORTED_BUT_NOT_MANDATED_DOS = 0 # Network Level Authentication (NLA) (passes creds instead of prompting after connect)
NLA_NOT_SUPPORTED_DOS = 1
SSL_SUPPORTED_BUT_NOT_MANDATED_MITM = 2
ONLY_RDP_SUPPORTED_MITM = 3
WEAK_RDP_ENCRYPTION_SUPPORTED = 4
NULL_RDP_ENCRYPTION_SUPPORTED = 5
FIPS_SUPPORTED_BUT_NOT_MANDATED = 6
LU_ISSUES = {
    NLA_SUPPORTED_BUT_NOT_MANDATED_DOS: 'NLA supported but not mandated DoS',
    NLA_NOT_SUPPORTED_DOS: 'NLA not supported DoS',
    SSL_SUPPORTED_BUT_NOT_MANDATED_MITM: 'SSL supported but not mandated MitM',
    ONLY_RDP_SUPPORTED_MITM: 'Only RDP supported MitM',
    WEAK_RDP_ENCRYPTION_SUPPORTED: 'Weak RDP encryption supported',
    NULL_RDP_ENCRYPTION_SUPPORTED: 'Null RDP encryption supported',
    FIPS_SUPPORTED_BUT_NOT_MANDATED: 'FIPS supported but not mandated',
}

#may not only be for x224 connection, maybe rename to RDPSocket
class RDPSocket:
    """Socket object for submitting requests to RDP server"""
    def __init__(self, hostname, port=3389, timeout=10):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.connect()

    def connect(self):
        """Open socket"""
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)# defaults
        self.s.settimeout(self.timeout)
        try:
            self.s.connect((self.hostname, self.port))
        except (socket.error, socket.timeout), e:
            if e[0] == 111 or e[0] == 'timed out': # 'timed out' is when settimeout is used
                e = ConnectionError('RDP server not listening: %s:%s' % (self.hostname, self.port))
            raise ConnectionError('Could not set up connection: %s' % e)

    def send(self, pdu):
        """Send specified PDU"""
        try:
            sbytes = self.s.send(pdu)
            if sbytes != len(pdu):
                raise ConnectionError('Could not send RDP payload')
            return self.s.recv(1024)
            # if no error, can continue to send
        except socket.error, e:
            if e[0] == 104:
                raise ConnectionError('Bad request or protocol not supported: %s' % e)

    def disconnect(self, s, pdu=None):
        """Send disconnect request"""
        try:
            pdu = x224DisconnectRequestPDU().pdu if not pdu else pdu
            sbytes = s.send(pdu)
            if sbytes != len(pdu):
                raise ConnectionError('Could not send RDP disconnection payload')
            s.close()
        except socket.error, e:
            raise ConnectionError('Error sending disconnect request: %s' % e)


# x224ConnectionRequest, x224ConnectionConfirm, MCSConnectInitial, MCSConnectResponse
class tpktHeader: # ln required for object contruction
    """TPKT Header used in connection requests and connection confirmations"""
    def __init__(self, resp=None, ver=3, res=0, ln=0):
        self.enc = '>BBH'   # (>) - big endian
        self.ver = ver      # (B) - version
        self.res = res      # (B) - reserved
        self.ln = ln        # (H) - length(entire PDU)
        if resp:
            self.unpack(resp)

    def pack(self):
        """Pack attrs to C structure"""
        return struct.pack(self.enc, self.ver, self.res, self.ln)

    def unpack(self, resp):
        """Unpack C structure to attrs"""
        self.ver, self.res, self.ln = struct.unpack(self.enc, resp)


# x224ConnectionRequestPDU
class RDP_NEG_REQ:
    """RDP negotiation request used in connection requests"""
    def __init__(self, type=1, flags=0, ln=8, rp=0):
        self.enc = '<BBHI'  # (<) - little endian
        self.type = type    # (B) - type
        self.flags = flags  # (B) - flags
        self.ln = ln        # (H) - length
        self.rp = rp        # (I) - requested protocols

    def pack(self):
        """Pack attrs to C structure"""
        return struct.pack(self.enc, self.type, self.flags, self.ln, self.rp)


# x224ConnectionRequestPDU
class x224Crq:
    """Connection request transport PDU used in connection requests"""
    def __init__(self, ln=14, cr=224, dst_ref=0, src_ref=0, co=0):
        # cookie omitted
        self.enc = '>BBHHB'     # (>) big endian
        self.ln = ln            # (B) - length (6=len this header, 8=len rdpNegData)
        self.cr = cr            # (B) - connection request confirm code
        self.dst_ref = dst_ref  # (H) - requested transport
        self.src_ref = src_ref  # (H) - selected transport
        self.co = co            # (B) - class option

    def pack(self):
        return struct.pack(self.enc, self.ln, self.cr, self.dst_ref, self.src_ref, self.co)


# x224ConnectionConfirmPDU
class RDP_NEG_RSP:
    """RDP negotiation response used in connection responses"""
    def __init__(self, resp):
        self.enc = '<BBHI'  # (<) - little endian
        # (B)type, (B)flats, (H)ln - length, (I)sp - selected protocol
        self.type, self.flags, self.ln, self.sp = struct.unpack(self.enc, resp)

    def sp_display(self):
        pass


# x224ConnectionConfirmPDU
class RDP_NEG_FAILURE:
    """RDP negotiation failure used in connection responses"""
    def __init__(self, resp):
        self.enc = '<BBHI'  # (<) - little endian
        # (B)type, (B)flats, (H)ln - length, (I)fc - failure code
        self.type, self.flags, self.ln, self.fc = struct.unpack(self.enc, resp)

# x224ConnectionConfirmPDU
class x224Ccf:
    """Connection confirmation transport PDU used in connection responses"""
    def __init__(self, resp):
        self.enc = '>BBHHB' # (>) big endian
        # (B)ln - length, (B)cc - connection code, dst_ref(H), src_ref(H), co(B) - class option
        self.ln, self.cc, self.dst_ref, self.src_ref, self.co = struct.unpack(self.enc, resp)


class TS_UD_SC_SEC1:
    """Server Security Data used in MCS Connect Response PDU"""
    def __init__(self, resp):
        self.enc = '<IIII' # (<) little endian
        # header = \x02\x0c + (H)length
        # ommitted - (I)header
        # (I)em - encryptionmethod, (I)el - encryption length, (I)random length, (I)cl - certificate length
        self.em, self.el, self.rl, self.cl = struct.unpack(self.enc, resp)

    def em_display(self):
        return LU_ENCRYPTION_METHOD.get(self.em)

    def el_display(self):
        return LU_ENCRYPTION_LEVEL.get(self.el)


# Requests:
class x224ConnectionRequest:
    """X.224 Connection Request PDU"""
    def __init__(self, rp=0): ## add options inputs
        tpktheader_len = 4  # fixed length
        self.x224crq = x224Crq()
        self.rdp_neg_data = RDP_NEG_REQ(rp=rp)
        self.x224_body = self.x224crq.pack() + self.rdp_neg_data.pack()
        self.tpktheader = tpktHeader(ln=len(self.x224_body) + tpktheader_len).pack()
        self.pdu = self.tpktheader + self.x224_body

class x224DisconnectRequest:
    """X.224 Disconnect Request PDU"""
    def __init__(self):
        tpktheader_len = 4  # fixed length
        # for Crq reduce the length from omitted rdp_neg_data and include 128 diconnect code
        self.x224crq = x224Crq(ln=6, cr=128)
        self.x224_body = self.x224crq.pack() # no rdp_neg_data
        self.tpktheader = tpktHeader(ln=len(self.x224_body) + tpktheader_len).pack()
        self.pdu = self.tpktheader + self.x224_body

# no RDP Security Layer if connection is refused (due to hybrid support only
class x224BasicRequest:## could make x224ConnectionRequest more generic to incorporate this
    """X.224 Connection Request PDU without rdpNegData"""
    def __init__(self):
        tpktheader_len = 4  # fixed length
        # for Crq reduce the length from omitted rdp_neg_data and include 128 diconnect code
        self.x224crq = x224Crq(ln=6)
        self.x224_body = self.x224crq.pack() # no rdp_neg_data
        self.tpktheader = tpktHeader(ln=len(self.x224_body) + tpktheader_len).pack()
        self.pdu = self.tpktheader + self.x224_body


class MCSConnectInitial:
    """MCS Connect Initial PDU"""
    def __init__(self, encryption_method):
        # Client MCS Connection Request does not specify encryption_level
        # grabbed from observed requests instead of constructing from scratch
        pdu =  '\x03\x00\x01\xa2\x02\xf0\x80\x7f\x65\x82\x01\x96\x04\x01\x01\x04\x01'
        pdu += '\x01\x01\x01\xff\x30\x20\x02\x02\x00\x22\x02\x02\x00\x02\x02\x02\x00'
        pdu += '\x00\x02\x02\x00\x01\x02\x02\x00\x00\x02\x02\x00\x01\x02\x02\xff\xff'
        pdu += '\x02\x02\x00\x02\x30\x20\x02\x02\x00\x01\x02\x02\x00\x01\x02\x02\x00'
        pdu += '\x01\x02\x02\x00\x01\x02\x02\x00\x00\x02\x02\x00\x01\x02\x02\x04\x20'
        pdu += '\x02\x02\x00\x02\x30\x20\x02\x02\xff\xff\x02\x02\xfc\x17\x02\x02\xff'
        pdu += '\xff\x02\x02\x00\x01\x02\x02\x00\x00\x02\x02\x00\x01\x02\x02\xff\xff'
        pdu += '\x02\x02\x00\x02\x04\x82\x01\x23\x00\x05\x00\x14\x7c\x00\x01\x81\x1a'
        pdu += '\x00\x08\x00\x10\x00\x01\xc0\x00\x44\x75\x63\x61\x81\x0c\x01\xc0\xd4'
        pdu += '\x00\x04\x00\x08\x00\x20\x03\x58\x02\x01\xca\x03\xaa\x09\x04\x00\x00'
        pdu += '\x28\x0a\x00\x00\x68\x00\x6f\x00\x73\x00\x74\x00\x00\x00\x00\x00\x00'
        pdu += '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        pdu += '\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00'
        pdu += '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        pdu += '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        pdu += '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        pdu += '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xca\x01\x00\x00\x00\x00'
        pdu += '\x00\x18\x00\x07\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        pdu += '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        pdu += '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        pdu += '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        pdu += '\x00\x00\x00\x00\x00\x04\xc0\x0c\x00\x09\x00\x00\x00\x00\x00\x00\x00'
        # insert encryption type into the PDU
        pdu += ('\x02\xc0\x0c\x00%s\x00\x00\x00\x00\x00\x00\x00\x03\xc0\x20\x00\x02'
                % struct.pack('<B', encryption_method))
        pdu += '\x00\x00\x00\x63\x6c\x69\x70\x72\x64\x72\x00\xc0\xa0\x00\x00\x72\x64'
        pdu += '\x70\x64\x72\x00\x00\x00\x80\x80\x00\x00'
        self.pdu = pdu


# Responses:
class x224ConnectionConfirm:# response to X.224 connection
    """X.224 Connection Confirm PDU"""
    def __init__(self, resp):
        self.resp = resp
        self.ln = len(resp) # use as check for response type
        if len(resp) != 11 and len(resp) != 19:
            raise ResponseError('X.224 connection confirm PDU of unexpected length (%d)' % self.ln)
        self.tpktheader = tpktHeader(resp[0:4])
        self.x224ccf = x224Ccf(resp[4:11])

        # see 3.3.5.3.2, rpd_ned_data SHOULD be returned, but not always
        if len(resp) == 11: #(4)tpktHeader, (7)x224Ccf
            self.rdp_neg_data = None

        if len(resp) == 19: # (4)tpktHeader, (7)x224Ccf, (8)RDP_NEG_RSP/RDP_NEG_FAILURE
            # check RDP NEG type
            rdp_neg_type = struct.unpack('<B', resp[11])[0]
            # self.rdp_neg_data may be RDP_NEG_RSP or RDP_NEG_FAILURE object
            if rdp_neg_type == RDP_NEG_TYPE_RSP:
                self.rdp_neg_data = RDP_NEG_RSP(resp[11:19])
            elif rdp_neg_type == RDP_NEG_TYPE_FAILURE:
                self.rdp_neg_data = RDP_NEG_FAILURE(resp[11:19])
            else:
                raise ResponseError('Unknown RDP_NEG_TYPE (%d)' % rdp_neg_type)


class MCSConnectResponse:#response to MCS connection
    """MCS Connect Response PDU"""
    def __init__(self, resp):
        self.resp = resp
        self.ln = len(resp) # use as check for response type
        self.tpktheader = tpktHeader(resp[0:4])
        #self.x224data = x224Data(resp[4:7] # not yet implemented
        if self.ln < 8:
           raise ResponseError('MCS response of unexpected length (%d)' % self.ln)
        self.decoded_resp = decoder.decode(resp[7:])[1]
        # self.decoded_resp
        try:
            security_data = re.search("\x02\x0c..(.{16})", self.decoded_resp, re.DOTALL).groups()[0]
            self.ts_ud_sc_sec1 = TS_UD_SC_SEC1(security_data)
        except AttributeError, e:
            raise ResponseError('Unknown error regexing TS_UD_SC_SEC1: %s' % e)


## figure out what to do with this and x224BasicRequest
def classic_rdp_security_support(rdpsocket):
    """True if supports MCS and encryption, this is a basic connection without NEG data"""
    try:
        cr = x224BasicRequest()
        rdpsocket.connect()
        resp = rdpsocket.send(cr.pdu)
        cc = x224ConnectionConfirm(resp)
        return True if cc.x224ccf.cc == 208 else False ## maybe don't check for 208, just connection
    except ConnectionError: # bad request, not bad connection
        return False

## abstract the protocol tests
## is there a test for hybrid_ex?
def protocol_rdp_support(rdpsocket):
    """(True, 0) if supports RDP Security"""
    try:
        cr = x224ConnectionRequest(rp=PROTOCOL_RDP)
        rdpsocket.connect()
        resp = rdpsocket.send(cr.pdu)
        cc = x224ConnectionConfirm(resp)
        if not cc.rdp_neg_data: # handle response with nordp_neg_data
            return (False, PROTOCOL_OLD)
        supported = True if cc.rdp_neg_data.type == RDP_NEG_TYPE_RSP else False
        return (supported, cc.rdp_neg_data.sp) if supported else (supported, cc.rdp_neg_data.fc)
    except ConnectionError: # bad socket.send, not bad socket.connect
        return (False, None)

def protocol_ssl_support(rdpsocket):
    """(True, 1) if supports TLS security"""
    try:
        cr = x224ConnectionRequest(rp=PROTOCOL_SSL)
        rdpsocket.connect()
        resp = rdpsocket.send(cr.pdu)
        cc = x224ConnectionConfirm(resp)
        if not cc.rdp_neg_data: # handle response with nordp_neg_data
            return (False, PROTOCOL_OLD)
        supported = True if cc.rdp_neg_data.type == RDP_NEG_TYPE_RSP else False
        return (supported, cc.rdp_neg_data.sp) if supported else (supported, cc.rdp_neg_data.fc)
    except ConnectionError: # bad socket.send, not bad socket.connect
        return (False, None)

def protocol_hybrid_support(rdpsocket):
    """(True, 3) if supports Hybrid"""
    try:
        cr = x224ConnectionRequest(rp=PROTOCOL_SSL_HYBRID)
        rdpsocket.connect()
        resp = rdpsocket.send(cr.pdu)
        cc = x224ConnectionConfirm(resp)
        if not cc.rdp_neg_data: # handle response with nordp_neg_data
            return (False, PROTOCOL_OLD)
        supported = True if cc.rdp_neg_data.type == RDP_NEG_TYPE_RSP else False
        return (supported, cc.rdp_neg_data.sp) if supported else (supported, cc.rdp_neg_data.fc)
    except ConnectionError: # bad socket.send, not bad socket.connect
        return (False, None)

def protocol_support(rdpsocket):
    """Conglomeration of protocol tests"""
    protocols = []
    failure_codes = []
    for test in [protocol_rdp_support, protocol_ssl_support, protocol_hybrid_support]:
        supported, type = test(rdpsocket)
        if supported and type not in protocols:
            protocols.append(type)
        elif not supported and type not in failure_codes and type in LU_FAILURE_CODE:
            failure_codes.append(type)
        elif not supported and type == PROTOCOL_OLD and type not in protocols:
            protocols.append(type)
    return protocols, failure_codes

def encryption_support(rdpsocket):
    methods = []
    levels = []
    for em in LU_ENCRYPTION_METHOD:
        try:
            rdpsocket.connect()
            resp = rdpsocket.send(x224BasicRequest().pdu)
            # check for response length 11
            x224ConnectionConfirm(resp)
            resp = rdpsocket.send(MCSConnectInitial(em).pdu)
            mcsr = MCSConnectResponse(resp)
            if mcsr.ts_ud_sc_sec1.em not in methods:
                methods.append(mcsr.ts_ud_sc_sec1.em)
            if mcsr.ts_ud_sc_sec1.el not in levels:
                levels.append(mcsr.ts_ud_sc_sec1.el)
        except ConnectionError:
            pass # do nothing, should be an unsupported request
        except ResponseError:
            raise # something went wrong
    return methods, levels


class RDPConfig:
    """RDP configuration representing queried data"""
    def __init__(self, hostname, port=3389, timeout=10):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.protocols = []
        self.failure_codes = []
        self.encryption_methods = []
        self.encryption_levels = []
        self.issues = []
        # Try to connect
        try:
            self.rdpsocket = RDPSocket(self.hostname, self.port, )
            self.alive = True
        except ConnectionError:
            self.alive = False

    def run_tests(self):
        """don't run rests unless alive"""
        if not self.alive:
            return
        # get protocol info
        self.protocols, self.failure_codes = protocol_support(self.rdpsocket)
        # get encryption info
        self.encryption_methods, self.encryption_levels = encryption_support(self.rdpsocket)
        # get issue info
        self.issues = []
        if PROTOCOL_HYBRID in self.protocols: #NLA DoS
            # see: http://en.wikipedia.org/wiki/Network_Level_Authentication
            if PROTOCOL_RDP in self.protocols or PROTOCOL_SSL in self.protocols:
                self.issues.append(NLA_SUPPORTED_BUT_NOT_MANDATED_DOS)
        else:
            self.issues.append(NLA_NOT_SUPPORTED_DOS)

        if PROTOCOL_RDP in self.protocols:
            if (PROTOCOL_SSL or PROTOCOL_HYBRID) in self.protocols:
                self.issues.append(SSL_SUPPORTED_BUT_NOT_MANDATED_MITM)
            else:
                self.issues.append(ONLY_RDP_SUPPORTED_MITM)

        if (ENCRYPTION_METHOD_40BIT or ENCRYPTION_METHOD_56BIT) in self.encryption_methods:
            self.issues.append(WEAK_RDP_ENCRYPTION_SUPPORTED)

        if ENCRYPTION_METHOD_NONE in self.encryption_methods:
            self.issues.append(NULL_RDP_ENCRYPTION_SUPPORTED)

        if ENCRYPTION_METHOD_FIPS in self.encryption_methods and len(self.encryption_methods) > 1:
            self.issues.append(FIPS_SUPPORTED_BUT_NOT_MANDATED)

    def results(self, fmt=None):
        print 'Target:      %s' % self.hostname
        print 'Port:        %s' % self.port if not self.port == 3389 else 'Port:        3389 (default)'
        print 'Host Status: UP' if self.alive else 'Host Status: DOWN'
        print

        if not self.alive:
            return

        print '[+] Supported Protocols:'
        if self.protocols:
            for p in self.protocols:
                print '\t%s' % LU_PROTOCOL[p]
            print
        else:
            print '\t(None)\n'

        print '[+] Supported Encryption Methods:'
        if self.encryption_methods:
            for em in self.encryption_methods:
                print '\t%s' % LU_ENCRYPTION_METHOD[em]
            print
        else:
            print '\t(None)\n'

        print '[+] Supported Encryption Levels:'
        if self.encryption_levels:
            for el in self.encryption_levels:
                print '\t%s' % LU_ENCRYPTION_LEVEL[el]
            print
        else:
            print '\t(None)\n'

        print '[+] Security Issues:'
        if self.issues:
            for i in self.issues:
                print '\t%s' % LU_ISSUES[i]
            print
        else:
            print '\t(None)\n'

        print '[+] Server Messages:'
        if self.failure_codes:
            for fc in self.failure_codes:
                print '\t%s' % LU_FAILURE_CODE[fc]
            print
        else:
            print '\t(None)\n'

issue_descriptions = """
Title:
Remote Desktop Encryption Vulnerabilities

Description:
There are multiple issues with the Remote Desktop configuration
- NLA supported but not mandated DoS
When a Remote Desktop (RDP) connection is initiated with an RDP server that does not require Network Level Authentication (NLA), the server will establish a session with the client and present the login screen before authentication takes place. This uses up resources on the server, and is a potential area for denial of service attacks. NLA delegates the user's credentials from the client through a client side Security Support Provider Interface (SSPI) and prompts the user to authenticate before establishing a session on the server.
- SSL supported but not mandated MitM
SSL encryption adds an additional layer of validation that the server must provide to the client. However, if hostnames and legitimate certificates are not used, the client will be presented with a warning dialog box that they must acknowledge.
- Weak RDP encryption supported
One or more of the following weak encryption methods is supported: 40 Bit, 56 Bit

Solution:
Navigate to System Properties -> Remote. Select the option for "Allow connection only from computers running Remote Desktop with Network Level Authentication (more secure)".
"""

if __name__ == "__main__":
    # test for now
    parser = argparse.ArgumentParser()# maybe add description?
    # rdpy.py [options] target(s)
    parser.add_argument('--port', default=3389, type=int,
        help='RDP listening port')
    parser.add_argument('--timeout', default=10, type=int,
        help='Connection timeout (in seconds)')
    parser.add_argument('-d', '--description', action='store_true',
        help='Display detailed vunlerability description information')
    parser.add_argument('hostname', nargs='+', type=str)
    args = parser.parse_args()
    alive = 0
    for h in args.hostname:
        rdpc = RDPConfig(h, args.port, args.timeout)
        if rdpc.alive:
            alive += 1
        rdpc.run_tests()
        rdpc.results()
        print '--------------------------------------------------\n'
    print 'Total Hosts:     %s' % len(args.hostname)
    print 'Listening Hosts: %s' % alive
    print
    if args.description:
        print '--------------------------------------------------\n'
        print issue_descriptions
        print

