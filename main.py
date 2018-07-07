#!/usr/bin/env python3.6

from dnsserver import dnsserver

def main():
    bind_address = ('127.0.0.1', 53)
    server = None
    try:
        server = dnsserver.get_dns_server(bind_address)
        server.serve_forever()
    except PermissionError:
        print('Permission denied - need to run as root?')
    except KeyboardInterrupt:
        print('Exiting...')
    finally:
        if server:
            server.shutdown()

if __name__ == "__main__":
    main()
