"""GraphQL introspection + WebSocket handshake. Loopback, sem rede externa."""

import socketserver
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import _pathshim  # noqa: F401

from agente import apiprobe


def _gql_server(introspection_on: bool):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            self.rfile.read(n)
            if self.path.rstrip("/") == "/graphql" and introspection_on:
                body = (b'{"data":{"__schema":{"queryType":{"name":"Query"},'
                        b'"types":[{"name":"A"},{"name":"B"},{"name":"C"}]}}}')
            else:
                body = b'{"errors":[{"message":"introspection is disabled"}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _ws_server(accept: bool):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.recv(2048)
            if accept:
                resp = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                        "Connection: Upgrade\r\n\r\n")
            else:
                resp = "HTTP/1.1 401 Unauthorized\r\n\r\n"
            self.request.sendall(resp.encode())
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestApiProbe(unittest.TestCase):
    def test_graphql_introspection_habilitada(self):
        srv = _gql_server(True)
        try:
            port = srv.server_address[1]
            r = apiprobe.graphql_introspection(f"http://127.0.0.1:{port}/graphql")
            self.assertTrue(r["enabled"])
            self.assertGreaterEqual(r["types"], 3)
            disc = apiprobe.discover_graphql(f"http://127.0.0.1:{port}/")
            self.assertTrue(disc and disc[0]["enabled"])
        finally:
            srv.shutdown(); srv.server_close()

    def test_graphql_introspection_desligada(self):
        srv = _gql_server(False)
        try:
            port = srv.server_address[1]
            r = apiprobe.graphql_introspection(f"http://127.0.0.1:{port}/graphql")
            self.assertFalse(r["enabled"])
            self.assertEqual(apiprobe.discover_graphql(f"http://127.0.0.1:{port}/"), [])
        finally:
            srv.shutdown(); srv.server_close()

    def test_find_ws_urls(self):
        txt = 'var a="wss://x.com/socket";const b=\'ws://y:8080/ws?t=1\';http://z/'
        urls = apiprobe.find_ws_urls(txt)
        self.assertIn("wss://x.com/socket", urls)
        self.assertTrue(any(u.startswith("ws://y:8080/ws") for u in urls))

    def test_ws_handshake_aceito(self):
        srv = _ws_server(True)
        try:
            port = srv.server_address[1]
            r = apiprobe.ws_handshake(f"ws://127.0.0.1:{port}/ws")
            self.assertTrue(r["accepted"])
            self.assertEqual(r["status"], 101)
        finally:
            srv.shutdown(); srv.server_close()

    def test_ws_handshake_recusado(self):
        srv = _ws_server(False)
        try:
            port = srv.server_address[1]
            r = apiprobe.ws_handshake(f"ws://127.0.0.1:{port}/ws")
            self.assertFalse(r["accepted"])
        finally:
            srv.shutdown(); srv.server_close()


if __name__ == "__main__":
    unittest.main()
