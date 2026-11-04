"""CI only: serve a directory over https on 127.0.0.1:18443 (the MDM exports accept https download URLs only).
usage: ci-https-server.py DIR CERT KEY"""
import functools, http.server, ssl, sys

handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=sys.argv[1])
server = http.server.ThreadingHTTPServer(("127.0.0.1", 18443), handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
