"""Bounded HTTP captive discovery; credentials are accepted only on HTTPS CGI."""
import ipaddress
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import threading
from .guest import portal_url
from .dns import Bounded


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):self.respond()
    def do_HEAD(self):self.respond()
    def do_POST(self):self.respond(405)
    def respond(self,status=302):
        self.connection.settimeout(5)
        settings=self.server.settings()
        allowed=bool(settings and ipaddress.ip_address(self.client_address[0]) in ipaddress.ip_network(settings['network']))
        self.send_response(status if allowed else 403)
        if allowed and status==302:self.send_header('Location',portal_url(settings))
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Length','0')
        self.send_header('Connection','close');self.end_headers();self.close_connection=True


class Server(Bounded,ThreadingHTTPServer):
    def get_request(self):
        request,address=super().get_request();request.settimeout(5);return request,address


class PortalServer:
    def __init__(self,address,settings):
        self.server=Server(address,Handler);self.server.settings=settings
        self.server.slots=threading.BoundedSemaphore(16)
        self.address=self.server.server_address
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
    def start(self):self.thread.start()
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join(timeout=5)
