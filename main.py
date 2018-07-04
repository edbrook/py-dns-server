#!/usr/bin/env python3.6

from dnsserver import dnsserver

def main():
    bind_address = ('127.0.0.1', 1053)
    try:
        server = dnsserver.get_dns_server(bind_address)
        server.serve_forever()
    except KeyboardInterrupt:
        print('Exiting...')
    finally:
        if server:
            server.shutdown()

if __name__ == "__main__":
    main()
