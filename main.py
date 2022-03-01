import socketserver
from helpers import *
from sip_proxy import SIPProxy


def run_proxy():
    proxy = socketserver.UDPServer((SIP_PROXY_HOST, SIP_PROXY_PORT), SIPProxy)
    proxy.serve_forever()


if __name__ == "__main__":
    run_proxy()
