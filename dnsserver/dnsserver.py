from enum import Enum
from socketserver import BaseRequestHandler, ThreadingMixIn, UDPServer

from .utils import bytes_to_int, int_to_bytes, display_message_bits


dnsserver = None


def get_dns_server(bind_address=None):
    global dnsserver
    if dnsserver is None:
        if bind_address is None:
            return None
        dnsserver = DNSServer(bind_address, DNSRequestHandler)
    return dnsserver


class DNSqr(Enum):
    QUERY = 0
    RESPONSE = 1


class DNSOpCode(Enum):
    QUERY = 0
    IQUERY = 1
    STATUS = 2


class DNSRCode(Enum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5


class DNSMessageException(Exception):
    pass


class DNSMessage:
    # See - https://www.ietf.org/rfc/rfc1035.txt
    __slots__ = [
        'id_',
        'qr', 'opcode', 'aa', 'tc', 'rd', 'ra', 'z', 'rcode',
        'queries',
        'answers',
        'authorities',
        'additional']

    def __init__(self):
        self.id_ = 0
        self.qr = DNSqr.QUERY
        self.opcode = DNSOpCode.QUERY
        self.aa = True
        self.tc = False
        self.rd = False
        self.ra = False
        self.z = 0
        self.rcode = DNSRCode.NXDOMAIN
        self.queries = []
        self.answers = []
        self.authorities = []
        self.additional = []
    
    def _encode_options(self):
        high_byte = 0
        low_byte = 0
        
        if self.qr == DNSqr.RESPONSE: high_byte |= 0x80
        high_byte |= (self.opcode.value & 0x0F) << 3
        if self.aa: high_byte |= 0x04
        if self.tc: high_byte |= 0x02
        if self.rd: high_byte |= 0x01

        if self.ra: low_byte |= 0x80
        low_byte |= (self.rcode.value & 0x0F)
        
        return bytes([high_byte, low_byte])
    
    def to_bytes(self):
        id_ = int_to_bytes(self.id_)
        codes = self._encode_options()
        qd_count = int_to_bytes(len(self.queries), 2)
        an_count = int_to_bytes(len(self.answers), 2)
        ns_count = int_to_bytes(len(self.authorities), 2)
        ar_count = int_to_bytes(len(self.additional), 2)
        return id_ + codes + qd_count + an_count + ns_count + ar_count

    def _set_options(self, options):
        high_byte = options[0]
        low_byte = options[1]
        
        if low_byte & 0x70 != 0:
            raise DNSMessageException("Z field should be 0 (zero)")

        self.qr = DNSqr((high_byte & 0x80) >> 7)
        self.opcode = DNSOpCode((high_byte & 0x78) >> 3)
        self.aa = (high_byte & 0x04) != 0
        self.tc = (high_byte & 0x02) != 0
        self.rd = (high_byte & 0x01) != 0
        self.ra = (low_byte & 0x80) != 0
        self.rcode = DNSRCode(low_byte & 0x0F)
        return ()

    @staticmethod
    def from_bytes(bytes_):
        message = DNSMessage()
        message.id_ = bytes_to_int(bytes_[0:2])
        message._set_options(bytes_[2:4])

        qdcount = bytes_to_int(bytes_[4:6])
        ancount = bytes_to_int(bytes_[6:8])
        nscount = bytes_to_int(bytes_[8:10])
        arcount = bytes_to_int(bytes_[10:12])
        
        return message
    
    def __repr__(self):
        ops = [self.qr.name, self.opcode.name]
        if self.aa: ops.append("aa")
        if self.tc: ops.append("tc")
        if self.rd: ops.append("rd")
        if self.ra: ops.append("ra")
        ops.append(self.rcode.name)

        return f"DNSMessage(id:{self.id_} ops:[{', '.join(ops)}]" \
            f" qry:{len(self.queries)}" \
            f" ans:{len(self.answers)}" \
            f" aut:{len(self.authorities)}" \
            f" add:{len(self.additional)})"


class DNSRequestHandler(BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        # cli_ip, cli_port = self.client_address

        in_msg = DNSMessage.from_bytes(data)
        res = DNSMessage()
        res.id_ = in_msg.id_
        res.rd = in_msg.rd
        if in_msg.rd:
            res.ra = True
        res.qr = DNSqr.RESPONSE
        
        print("<<<<<")
        print(in_msg)
        display_message_bits(in_msg.to_bytes())

        print(">>>>>")
        print(res)
        display_message_bits(res.to_bytes())
        
        socket.sendto(res.to_bytes(), self.client_address)


class DNSServer(ThreadingMixIn, UDPServer):
    pass
