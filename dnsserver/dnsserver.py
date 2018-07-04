from socketserver import BaseRequestHandler, ThreadingMixIn, UDPServer


dnsserver = None


def get_dns_server(bind_address=None):
    global dnsserver
    if dnsserver is None:
        if bind_address is None:
            return None
        dnsserver = DNSServer(bind_address, DNSRequestHandler)
    return dnsserver


class DNSRequestHandler(BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        # cli_ip, cli_port = self.client_address
        id_ = data[0:2]
        # https://www.ietf.org/rfc/rfc1035.txt
        # QR:1 | Opcode:4 | AA:1 | TC:1 | RD:1
        # RA:1 | Z:3 | RCODE:4 
        codes = bytes([0b10000001, 0b10000000])
        qd_count = b'\x00\x00'
        an_count = b'\x00\x00'
        ns_count = b'\x00\x00'
        ar_count = b'\x00\x00'
        res =  id_ + codes + qd_count + an_count + ns_count + ar_count
        print(f'<<< {data}')
        print(f'>>> {res}')
        # bits = [bin(data[n])[2:].zfill(8) for n in range(len(data))]
        # print('\n'.join([f'{bits[n]} {bits[n+1]}' for n in range(0, len(bits),2)]))
        socket.sendto(res, self.client_address)


class DNSServer(ThreadingMixIn, UDPServer):
    pass
