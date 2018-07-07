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


_msg_types = [
    'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 'MB', 'MG', 'MR',
    'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT']
_msg_types_map = dict(zip(_msg_types, range(1, 17)))
DNSType = Enum('DNSType', _msg_types_map)
del _msg_types


_msg_qtypes = ['AXFR', 'MAILB', 'MAILA', 'ALL']
_msg_qtypes_map = _msg_types_map.copy()
_msg_qtypes_map.update(dict(zip(_msg_qtypes, range(252, 256))))
DNSQType = Enum('DNSQType', _msg_qtypes_map)
del _msg_qtypes, _msg_types_map, _msg_qtypes_map


_msg_class = ['IN', 'CS', 'CH', 'HS']
_msg_class_map = dict(zip(_msg_class, range(1, 5)))
DNSClass = Enum('DNSClass', _msg_class_map)
del _msg_class


_msg_qclass_map = _msg_class_map.copy()
_msg_qclass_map['ALL'] = 255
DNSQClass = Enum('DNSQClass', _msg_qclass_map)
del _msg_class_map, _msg_qclass_map


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


class DNSMessageCompression:
    @classmethod
    def decode_names(cls, bytes_, offset):
        names = []
        total_bytes_read = 0
        byte_count = len(bytes_)
        while offset < byte_count:
            name, bytes_read = cls._decode_name(bytes_, total_bytes_read + offset)
            total_bytes_read += bytes_read
            if name == '.':
                if len(names) == 0:
                    names.append(name)
                break
            names.append(name)
        return names, total_bytes_read

    @classmethod
    def _decode_name(cls, bytes_, offset):
        name = []
        bytes_read = 0

        while bytes_read < len(bytes_):
            j = bytes_read + offset
            n = bytes_[j]

            if n == 0:
                bytes_read += 1
                break
            
            if n & 0xc0 == 0xc0:
                name.append(cls._decode_label(bytes_, j))
                bytes_read += 2
                break

            name.append(''.join([chr(byte) for byte in bytes_[j+1:j+1+n]]))
            bytes_read += 1 + n

        return ''.join(('.'.join(name), '.')), bytes_read
    
    @classmethod
    def _decode_label(cls, bytes_, i):
        offset = (bytes_[i] & 0x3f) << 8
        offset += bytes_[i + 1]
        name, _ = cls._decode_name(bytes_, offset)
        return name[:-1]


class DNSQuestionSection:
    def __init__(self):
        self.names = []
        self.qtype = None
        self.qclass = None
    
    def to_bytes(self):
        return b''

    @staticmethod
    def from_bytes(bytes_, offset=12):
        qs = DNSQuestionSection()
        
        names, bytes_read = DNSMessageCompression.decode_names(bytes_, offset)
        qs.names = names

        i = offset + bytes_read
        qs.qtype = bytes_to_int(bytes_[i:i+2])
        qs.qclass = bytes_to_int(bytes_[i+2:i+4])

        return qs, bytes_read + 4
    
    def __len__(self):
        return len(self.to_bytes())
    
    def __repr__(self):
        return f"QS({self.names})"


class DNSAnswerSection:
    pass


class DNSAuthoritySection:
    pass


class DNSAdditionalSection:
    pass


class DNSMessage:
    # See - https://www.ietf.org/rfc/rfc1035.txt
    # See - https://www.ietf.org/rfc/rfc2065.txt (ad / cd)
    __slots__ = [
        'id_',
        'qr', 'opcode', 'aa', 'tc', 'rd', 'ra', 'z', 'ad', 'cd', 'rcode',
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
        self.ad = False
        self.cd = False
        self.rcode = DNSRCode.NXDOMAIN
        self.queries = []
        self.answers = []
        self.authorities = []
        self.additional = []
    
    def add_question_section(self, section):
        if not isinstance(section, DNSQuestionSection):
            raise DNSMessageException("Attempting to add invalid Question Section")
        self.queries.append(section)
    
    def add_answer_section(self, section):
        pass
    
    def add_authority_section(self, section):
        pass
    
    def add_additional_section(self, section):
        pass

    def to_bytes(self):
        id_ = int_to_bytes(self.id_)
        codes = self._encode_options()
        qd_count = int_to_bytes(len(self.queries), 2)
        an_count = int_to_bytes(len(self.answers), 2)
        ns_count = int_to_bytes(len(self.authorities), 2)
        ar_count = int_to_bytes(len(self.additional), 2)
        return id_ + codes + qd_count + an_count + ns_count + ar_count
    
    def _encode_options(self):
        high_byte = 0
        low_byte = 0
        
        if self.qr == DNSqr.RESPONSE: high_byte |= 0x80
        high_byte |= (self.opcode.value & 0x0F) << 3
        if self.aa: high_byte |= 0x04
        if self.tc: high_byte |= 0x02
        if self.rd: high_byte |= 0x01

        if self.ra: low_byte |= 0x80
        if self.ad: low_byte |= 0x20
        if self.cd: low_byte |= 0x10
        low_byte |= (self.rcode.value & 0x0F)
        
        return bytes([high_byte, low_byte])

    def _set_options_from_bytes(self, options):
        high_byte = options[0]
        low_byte = options[1]
        
        if low_byte & 0x40 != 0:
           raise DNSMessageException("Z field should be 0 (zero)")

        self.qr = DNSqr((high_byte & 0x80) >> 7)
        self.opcode = DNSOpCode((high_byte & 0x78) >> 3)
        self.aa = (high_byte & 0x04) != 0
        self.tc = (high_byte & 0x02) != 0
        self.rd = (high_byte & 0x01) != 0
        self.ra = (low_byte & 0x80) != 0
        self.z  = (low_byte & 0x40) != 0
        self.ad = (low_byte & 0x20) != 0
        self.cd = (low_byte & 0x10) != 0
        self.rcode = DNSRCode(low_byte & 0x0F)

    @staticmethod
    def from_bytes(bytes_):
        message = DNSMessage()
        message.id_ = bytes_to_int(bytes_[0:2])
        message._set_options_from_bytes(bytes_[2:4])

        qdcount = bytes_to_int(bytes_[4:6])
        ancount = bytes_to_int(bytes_[6:8])
        nscount = bytes_to_int(bytes_[8:10])
        arcount = bytes_to_int(bytes_[10:12])

        offset = 12
        for _ in range(qdcount):
            qs, bytes_read = DNSQuestionSection.from_bytes(bytes_, offset)
            message.add_question_section(qs)
            offset += bytes_read
        
        return message
    
    def __len__(self):
        return len(self.to_bytes())
    
    def __repr__(self):
        ops = [self.qr.name, self.opcode.name]
        if self.aa: ops.append("aa")
        if self.tc: ops.append("tc")
        if self.rd: ops.append("rd")
        if self.ra: ops.append("ra")
        if self.ad: ops.append("ad")
        if self.cd: ops.append("cd")
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
        res.ra = in_msg.rd
        res.qr = DNSqr.RESPONSE
        
        print("<<<<<")
        print(data)
        display_message_bits(data)
        print("<<<<<")
        print(in_msg)
        display_message_bits(in_msg.to_bytes())

        print(">>>>>")
        print(res)
        display_message_bits(res.to_bytes())

        for qs in in_msg.queries:
            print(f"<<< {qs}")

        for qs in res.queries:
            print(f">>> {qs}")
        
        socket.sendto(res.to_bytes(), self.client_address)


class DNSServer(ThreadingMixIn, UDPServer):
    pass
