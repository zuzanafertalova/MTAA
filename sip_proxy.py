###
#    Ported library to Python3 from https://raw.githubusercontent.com/tirfil/PySipFullProxy/master/sipfullproxy.py by Philippe THIRION
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
# 
###
import time
from typing import Any
from socketserver import BaseServer, BaseRequestHandler
from helpers import *
import re

SIP_REQUEST_URI = re.compile("^([^ ]*) sip:([^ ]*) SIP/2.0")
SIP_CODE = re.compile("^SIP/2.0 ([^ ]*)")

SIP_URI = re.compile("sip:([^@]*)@([^;>$]*)")
SIP_ADDR = re.compile("sip:([^ ;>$]*)")

SIP_TO = re.compile("^To:")
SIP_TO_SHORT = re.compile("^t:")

SIP_FROM = re.compile("^From:")
SIP_FROM_SHORT = re.compile("^f:")

SIP_CONTACT = re.compile("^Contact:")
SIP_CONTACT_SHORT = re.compile("^m:")
SIP_CONTACT_EXPIRES = re.compile("expires=([^;$]*)")


SIP_EXPIRES = re.compile("^Expires: (.*)$")

SIP_VIA = re.compile("^Via:")
SIP_VIA_SHORT = re.compile("^v:")

SIP_TAG = re.compile(";tag")

SIP_BRANCH = re.compile(";branch=([^;]*)")
SIP_RPORT = re.compile(";rport$|;rport;")

SIP_CONTENT_LENGTH = re.compile("^Content-Length:")
SIP_CONTENT_LENGTH_SHORT = re.compile("^l:")

SIP_ROUTE = re.compile("^Route:")

SIP_REGISTER = re.compile("^REGISTER")
SIP_INVITE = re.compile("^INVITE")
SIP_ACK = re.compile("^ACK")
SIP_PRACK = re.compile("^PRACK")
SIP_CANCEL = re.compile("^CANCEL")
SIP_BYE = re.compile("^BYE")
SIP_OPTIONS = re.compile("^OPTIONS")
SIP_SUBSCRIBE = re.compile("^SUBSCRIBE")
SIP_PUBLISH = re.compile("^PUBLISH")
SIP_NOTIFY = re.compile("^NOTIFY")
SIP_INFO = re.compile("^INFO")
SIP_MESSAGE = re.compile("^MESSAGE")
SIP_REFER = re.compile("^REFER")
SIP_UPDATE = re.compile("^UPDATE")

SIP_CODE_BUSY_HERE = re.compile("SIP\/2.0 486 Busy Here")

SIP_REGISTRAR = dict()

SIP_TOP_VIA = "Via: SIP/2.0/UDP {}:{}".format(SIP_PROXY_HOST, SIP_PROXY_PORT)
SIP_RECORD_ROUTE = "Record-Route: <sip:{}:{};lr>".format(SIP_PROXY_HOST, SIP_PROXY_PORT)


class SIPProxy(BaseRequestHandler):
    def __init__(self, request: Any, client_address: Any, server: BaseServer):
        super().__init__(request, client_address, server)

        self.host = client_address[0]
        self.port = client_address[1]
        self.data = None
        self.socket = None

    # driver funkcia na spracovanie SIP requestov
    def process_request(self):
        if len(self.data) > 0:
            # uloz aky request prisiel do premennej request_uri
            request_uri = self.data[0]

            # podla regexu najdi typ requestu a spracuj podla neho poziadavku

            # ked pride REGISTER -> registracia pouzivatela do ustredne
            if SIP_REGISTER.search(request_uri):
                self.handle_sip_register()
            # INVITE - niekto zacal hovor
            elif SIP_INVITE.search(request_uri):
                self.handle_sip_invite()
            # ACK - potvrdenie napr. zacatia hovoru a pod.
            elif SIP_ACK.search(request_uri):
                self.handle_sip_ack()
            elif SIP_BYE.search(request_uri):
                self.handle_sip_non_invite()
            elif SIP_CANCEL.search(request_uri):
                self.handle_sip_non_invite()
            elif SIP_OPTIONS.search(request_uri):
                self.handle_sip_non_invite()
            elif SIP_INFO.search(request_uri):
                self.handle_sip_non_invite()
            elif SIP_MESSAGE.search(request_uri):
                self.handle_sip_non_invite()
            elif SIP_REFER.search(request_uri):
                self.handle_sip_non_invite()
            elif SIP_PRACK.search(request_uri):
                self.handle_sip_non_invite()
            elif SIP_UPDATE.search(request_uri):
                self.handle_sip_non_invite()
            elif SIP_SUBSCRIBE.search(request_uri):
                self.send_response("200 POHODKA")
            elif SIP_PUBLISH.search(request_uri):
                self.send_response("200 POHODKA")
            elif SIP_NOTIFY.search(request_uri):
                self.send_response("200 POHODKA")
            # ak sa nejededna o ziaden z kodov vyssie, posli kod do funckie na spracuvanie
            # SIP kodov, moze sem napr. dojst ked softphone vytaca a prichadza "Rining", "Trying" a podobne
            elif SIP_CODE.search(request_uri):
                self.handle_sip_code()

    # funkcia na spracuvanie SIP kodov
    def handle_sip_code(self):
        sip_origin = self.get_sip_origin()

        if len(sip_origin) > 0:
            if sip_origin in SIP_REGISTRAR.keys():
                sock, client_addr = self.get_socket_info(sip_origin)

                self.data = self.remove_route_header()
                data = self.remove_top_via()
                text = "\r\n".join(data)

                for line in data:
                    if SIP_CODE_BUSY_HERE.search(line):
                        print(line)

                sock.sendto(text.encode(), client_addr)

    # vypise aktualny obsah registrovanych pouzivatelov v ustredni
    def dump_registrar(self):
        for data in SIP_REGISTRAR.items():
            print(data)

    # funkcia na registraciu uzivatelov do ustredne
    def handle_sip_register(self):
        sip_from = ""
        sip_contact = ""
        sip_contact_expires = ""
        sip_header_expires = ""
        sip_authorization = ""
        sip_expires = 0
        sip_validity = 0
        sip_index = 0
        sip_auth_index = 0
        data = []

        size = len(self.data)

        for line in self.data:
            if SIP_TO.search(line) or SIP_TO_SHORT.search(line):
                result = SIP_URI.search(line)
                if result:
                    sip_from = "{}@{}".format(result.group(1), result.group(2))

            if SIP_CONTACT.search(line) or SIP_CONTACT_SHORT.search(line):
                result = SIP_URI.search(line)
                if result:
                    sip_contact = result.group(2)
                else:
                    result = SIP_ADDR.search(line)
                    if result:
                        sip_contact = result.group(1)
                result = SIP_CONTACT_EXPIRES.search(line)
                if result:
                    sip_contact_expires = result.group(1)
            result = SIP_EXPIRES.search(line)
            if result:
                sip_header_expires = result.group(1)

        if len(sip_contact_expires) > 0:
            sip_expires = int(sip_contact_expires)
        elif len(sip_header_expires) > 0:
            sip_expires = int(sip_header_expires)

        if sip_expires == 0:
            if sip_from in SIP_REGISTRAR.keys():
                del SIP_REGISTRAR[sip_from]
                self.send_response("200 POHODKA")
                return
        else:
            now = int(time.time())
            sip_validity = now + sip_expires

        SIP_REGISTRAR[sip_from] = [sip_contact, self.socket, self.client_address, sip_validity]

        self.dump_registrar()
        self.send_response("200 POHODKA")

    # funkcia na spracovanie INVITE SIP
    def handle_sip_invite(self):
        print("Got INVITE request")

        sip_origin = self.get_sip_origin()

        if len(sip_origin) == 0 or sip_origin not in SIP_REGISTRAR.keys():
            self.send_response("400 Zla poziadavka pre INVITE")
            return

        sip_destination = self.get_sip_destination()

        if len(sip_destination) > 0:
            print("Destination: {}".format(sip_destination))

            if sip_destination in SIP_REGISTRAR.keys():
                sock, client_addr = self.get_socket_info(sip_destination)

                self.data = self.add_top_via()
                data = self.remove_route_header()

                data.insert(1, SIP_RECORD_ROUTE)
                text = "\r\n".join(data)

                sock.sendto(text.encode(), client_addr)
            else:
                self.send_response("480 Docasne nedostupne")

        else:
            self.send_response("500 Chyba Servera")

    def handle_sip_non_invite(self):
        sip_origin = self.get_sip_origin()

        if len(sip_origin) == 0 or sip_origin not in SIP_REGISTRAR.keys():
            self.send_response("400 Zla poziadavka pre NON-INVITE")
            return

        sip_destination = self.get_sip_destination()
        if len(sip_destination) > 0:
            if sip_destination in SIP_REGISTRAR.keys() and self.check_sip_validity(sip_destination):
                sock, client_addr = self.get_socket_info(sip_destination)
                self.data = self.add_top_via()
                data = self.remove_route_header()

                data.insert(1, SIP_RECORD_ROUTE)
                text = "\r\n".join(data)

                sock.sendto(text.encode(), client_addr)
            else:
                self.send_response("406 Neprijatelne serverom")
        else:
            self.send_response("500 Chyba servera")

    def handle_sip_ack(self):
        sip_destination = self.get_sip_destination()

        if len(sip_destination) > 0:
            if sip_destination in SIP_REGISTRAR.keys():
                sock, client_addr = self.get_socket_info(sip_destination)

                self.data = self.add_top_via()
                data = self.remove_route_header()

                data.insert(1, SIP_RECORD_ROUTE)
                text = "\r\n".join(data)

                sock.sendto(text.encode(), client_addr)

    def remove_route_header(self):
        data = []

        for line in self.data:
            if not SIP_ROUTE.search(line):
                data.append(line)

        return data

    def add_top_via(self):
        branch = str()
        data = []

        for line in self.data:
            if SIP_VIA.search(line) or SIP_VIA_SHORT.search(line):
                result = SIP_BRANCH.search(line)
                if result:
                    branch = result.group(1)
                    via = "{};branch={}".format(SIP_TOP_VIA, branch)
                    data.append(via)

                if SIP_RPORT.search(line):
                    text = "received={};rport={}".format(self.client_address[0], self.client_address[1])
                    via = line.replace("rport", text)
                else:
                    text = "received={}".format(self.client_address[0])
                    via = "{};{}".format(line, text)

                data.append(via)
            else:
                data.append(line)

        return data

    def remove_top_via(self):
        data = []
        for line in self.data:
            if SIP_VIA.search(line) or SIP_VIA_SHORT.search(line):
                if not line.startswith(SIP_TOP_VIA):
                    data.append(line)
            else:
                data.append(line)

        return data

    def get_socket_info(self, sip_uri):
        addr_port, socket, client_addr, validity = SIP_REGISTRAR[sip_uri]

        return (socket, client_addr)

    def check_sip_validity(self, sip_uri):
        addr_port, socket, client_addr, validity = SIP_REGISTRAR[sip_uri]

        now = int(time.time())

        if validity > now:
            return True
        else:
            del SIP_REGISTRAR[sip_uri]
            print("Registration for {} has expired!".format(sip_uri))
            return False

    def get_sip_origin(self):
        origin = str()

        for line in self.data:
            if SIP_FROM.search(line) or SIP_FROM_SHORT.search(line):
                result = SIP_URI.search(line)
                if result:
                    origin = "{}@{}".format(result.group(1), result.group(2))
                break

        return origin

    def get_sip_destination(self):
        dest = str()

        for line in self.data:
            if SIP_TO.search(line) or SIP_TO_SHORT.search(line):
                result = SIP_URI.search(line)
                if result:
                    dest = "{}@{}".format(result.group(1), result.group(2))
                break

        return dest

    def send_response(self, response_code):
        request_uri = "SIP/2.0 {}".format(response_code)
        self.data[0] = request_uri
        index = 0
        data = []

        for line in self.data:
            data.append(line)
            if SIP_TO.search(line) or SIP_TO_SHORT.search(line):
                if not SIP_TAG.search(line):
                    data[index] = "{}{}".format(line, ";tag=299299")

            if SIP_VIA.search(line) or SIP_VIA_SHORT.search(line):
                if SIP_RPORT.search(line):
                    text = "received={};rport={}".format(self.client_address[0], self.client_address[1])
                    data[index] = line.replace("rport", text)

            if SIP_CONTENT_LENGTH.search(line):
                data[index] = "Content-Length: 0"
            if SIP_CONTENT_LENGTH_SHORT.search(line):
                data[index] = "l: 0"

            index += 1

            if line == "":
                break

        data.append("")
        text = "\r\n".join(data)

        self.socket.sendto(text.encode(), self.client_address)

    def handle(self) -> None:
        data = self.request[0]

        self.data = data.decode().split("\r\n")

        self.socket = self.request[1]

        request_uri = self.data[0]

        if SIP_REQUEST_URI.search(request_uri) or SIP_CODE.search(request_uri):
            print("<--- SIP REQUEST --->")
            print(request_uri)
            print("<--- END SIP REQUEST --->")
            self.process_request()



