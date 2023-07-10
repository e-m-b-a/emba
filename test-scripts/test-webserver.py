from http.server import BaseHTTPRequestHandler, HTTPServer

class WebServer():
    authorization_code = None
def __init__(self, hostName, serverPort):
    self.hostName = hostName
    self.serverPort = serverPort
    self.server = HTTPServer((self.hostName, self.serverPort), CallbackHandler)

def get_auth_code(self):
    self.server.handle_request()

class CallbackHandler(BaseHTTPRequestHandler):
def do_GET(self):
    WebServer.authorization_code = self.path.split('?')[1].split('=')[1]
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write(b'<html><body><h1>Authorization Successful!</h1></body>    
    </html>')
