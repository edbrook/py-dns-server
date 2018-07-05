from enum import Enum
from socketserver import BaseRequestHandler, ThreadingMixIn, UDPServer


dnsserver = None


def get_dns_server(bind_address=None):
    global dnsserver
    if dnsserver is None:
        if bind_address is None:
            return None
        dnsserver = DNSServer(bind_address, DNSRequestHandler)
    return dnsserver

def _int_to_bytes(value, min_length=1):                                             
    values = []
    while value > 0 or len(values) < min_length:
        values.append(value & 0xFF) 
        value >>= 8
    return bytes(values[::-1])

def _bytes_to_int(bytes_):
    i = 0
    for byte in bytes_:
        i <<= 8
        i += int(byte) 
    return i


def display(data):
    bits = [bin(data[n])[2:].zfill(8) for n in range(len(data))]
    print('\n'.join([f'{bits[n]} {bits[n+1]}' for n in range(0, len(bits),2)]))


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



class DNSResponse:
    def __init__(self, id_):
        # See - https://www.ietf.org/rfc/rfc1035.txt
        self.id_ = id_
        self.qr = DNSqr.QUERY
        self.opcode = DNSOpCode.QUERY
        self.aa = True
        self.tc = False
        self.rd = True
        self.ra = False
        self.z = 0
        self.rcode = DNSRCode.NXDOMAIN
        self.querys = []
        self.answers = []
        self.authories = []
        self.additionals = []
    
    def get_response(self):
        codes = bytes([0b10000001, 0b10000000])
        qd_count = b'\x00\x00'
        an_count = b'\x00\x00'
        ns_count = b'\x00\x00'
        ar_count = b'\x00\x00'
        return _int_to_bytes(self.id_) + codes + qd_count + an_count + ns_count + ar_count


class DNSRequestHandler(BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        # cli_ip, cli_port = self.client_address
        id_ = _bytes_to_int(data[0:2])
        res = DNSResponse(id_).get_response()
        
        print(f'<<< {data}')
        display(data)
        
        print(f'>>> {res}')
        display(res)
        
        socket.sendto(res, self.client_address)


class DNSServer(ThreadingMixIn, UDPServer):
    pass
