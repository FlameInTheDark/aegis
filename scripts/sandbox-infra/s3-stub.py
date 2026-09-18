#!/usr/bin/env python3
"""Minimal S3-compatible stub for sandbox e2e runs.

Implements just enough of the S3 protocol for the platform's minio-go
client: bucket existence probes (GET /{bucket}?location=...), bucket
creation (PUT /{bucket}) and object reads (GET /{bucket}/reports/...).
Request signatures are ignored on purpose — the stub only exists so the
server can boot with a live object store and handlers can be exercised
end-to-end without Docker.
"""
import re
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, HTTPServer

ARTIFACT = b"<html><body><h1>Aegis demo report</h1><p>ok-e2e-artifact</p></body></html>"
NOW = formatdate(usegmt=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code=200, body=b"", ctype="application/xml", etag=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if etag:
            self.send_header("ETag", etag)
            self.send_header("Last-Modified", NOW)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def do_HEAD(self):
        if re.match(r"^/[^/]+/?$", self.path):
            self._send()
        else:
            self._send(404)

    def do_GET(self):
        if "location" in self.path and re.match(r"^/[^/]+\?", self.path):
            self._send(body=b"<LocationConstraint/>")
            return
        if re.match(r"^/[^/]+/(reports/.+)$", self.path):
            self._send(body=ARTIFACT, ctype="text/html", etag='"e2e-artifact-1"')
            return
        self._send(404)

    def do_PUT(self):
        # drain any body the client sent (bucket create is empty)
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if re.match(r"^/[^/]+/?$", self.path):
            self._send()
        else:
            self._send(404)


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9002
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
