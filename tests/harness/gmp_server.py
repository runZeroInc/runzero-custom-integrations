"""Declarative GMP responder for custom integration tests.

The Greenbone Management Protocol is XML over a stream socket, not HTTP, so
`FixtureServer` cannot drive `greenbone/greenbone.star` at all -- that
script makes zero HTTP requests and reaches gvmd through `socket.tls()` or an
SSH-forwarded UNIX socket. This server speaks the wire protocol instead.

It is deliberately shaped like `server.py`: ordered routes, one matcher plus a
list of responses, and a recorded request log the runner asserts against. A
request is recorded with method "GMP" and path set to the command name, so the
runner's existing `requests_include` matchers work unchanged.

Two gvmd behaviours are modelled because the importer depends on both, and both
were confirmed against a live gvmd 25.2.1 (GMP 22.6):

  * Responses carry no XML declaration and no trailing newline. Elements arrive
    back to back on one connection, so the client can only find the end of a
    response by tracking tag depth.
  * gvmd HANGS UP after refusing a command sent before `<authenticate>`. A
    response may therefore set `"close": true` to close the connection instead
    of waiting for the next request.
"""

import os
import re
import socket
import ssl
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

# See server.py: a thread per accepted connection is bounded by nothing the
# scenario controls, so this is a ceiling. GMP scenarios use one connection at
# a time and the pool grows lazily, so the number costs nothing in practice.
GMP_MAX_WORKERS = int(os.environ.get("GMP_MAX_WORKERS", "1000"))
GMP_LISTEN_BACKLOG = int(os.environ.get("GMP_LISTEN_BACKLOG", "1000"))

# The command name is the first tag of the request, e.g. `<get_reports .../>`.
_COMMAND_RE = re.compile(r"<\s*([A-Za-z_][\w.-]*)")


def read_element(recv):
    """Read exactly one top-level XML element using the importer's own rule.

    gvmd escapes '<' and '>' inside element text, so every '>' ends a tag and
    tag depth alone identifies the end of a top-level element. `recv` is a
    callable returning up to n bytes, or b"" at EOF.
    """
    parts = []
    depth = 0
    started = False
    pending = b""
    while True:
        chunk = recv(4096) if not pending else pending
        pending = b""
        if not chunk:
            return b"".join(parts) if parts else b""
        parts.append(chunk)
        blob = b"".join(parts)
        # Re-scan from scratch; requests are short, so this stays cheap and
        # avoids a partial-tag state machine.
        depth = 0
        started = False
        end = -1
        i = 0
        while True:
            gt = blob.find(b">", i)
            if gt < 0:
                break
            tok = blob[i:gt + 1]
            lt = tok.rfind(b"<")
            i = gt + 1
            if lt < 0:
                continue
            tag = tok[lt:]
            if tag.startswith(b"</"):
                depth -= 1
            elif tag.startswith(b"<?") or tag.startswith(b"<!"):
                continue
            elif tag.endswith(b"/>"):
                started = True
            else:
                depth += 1
                started = True
            if started and depth <= 0:
                end = i
                break
        if end >= 0:
            return blob[:end]


def _self_signed(dirpath):
    """Generate a throwaway EC cert. The script pins nothing and the scenario
    sets tls_disable_validation, so this only has to complete a handshake."""
    cert = os.path.join(dirpath, "cert.pem")
    key = os.path.join(dirpath, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-keyout", key, "-out", cert, "-days", "1", "-nodes",
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
        check=True, capture_output=True,
    )
    return cert, key


class GMPRoute(object):
    """One matcher plus the ordered responses it hands back."""

    def __init__(self, spec):
        self.name = spec.get("name", "")
        match = spec.get("match", {})
        self.command = match.get("command")
        self.body_contains = match.get("body_contains")
        self.body_regex = re.compile(match["body_regex"]) if match.get("body_regex") else None
        self.responses = spec.get("responses") or [{}]
        self.when_exhausted = spec.get("when_exhausted", "repeat_last")
        self.calls = 0

    def matches(self, command, body):
        if self.command is not None and self.command != command:
            return False
        if self.body_contains is not None and self.body_contains not in body:
            return False
        if self.body_regex is not None and not self.body_regex.search(body):
            return False
        return True

    def next_response(self):
        index = self.calls
        self.calls += 1
        if index < len(self.responses):
            return self.responses[index]
        if self.when_exhausted == "repeat_last":
            return self.responses[-1]
        if self.when_exhausted == "empty":
            return {"xml": '<gmp_response status="200" status_text="OK"/>'}
        return {"xml": '<gmp_response status="500" status_text="fixture route exhausted"/>',
                "close": True}


class GMPServer(object):
    """Serves one GMP scenario over TLS and records every request received."""

    def __init__(self, spec, basedir):
        self.routes = [GMPRoute(r) for r in spec.get("routes", [])]
        self.default = spec.get("default_response", {
            "xml": '<gmp_response status="404" status_text="no fixture route"/>',
            "close": True,
        })
        self.basedir = basedir
        self.requests = []
        self.lock = threading.Lock()
        self._sock = None
        self._thread = None
        self._ctx = None
        self._certdir = None
        self._pool = None
        self._stop = False

    def _body_for(self, spec):
        """A response is either inline `xml` or an `xml_file` beside the
        scenario. Recorded transcripts are large and are the point of the test,
        so they live as real .xml files rather than one-line JSON strings."""
        if "xml_file" in spec:
            path = os.path.join(self.basedir, spec["xml_file"])
            with open(path, "rb") as handle:
                return handle.read()
        return (spec.get("xml") or "").encode()

    def _serve_conn(self, conn):
        try:
            while True:
                raw = read_element(conn.recv)
                if not raw:
                    return
                body = raw.decode("utf-8", "replace")
                match = _COMMAND_RE.search(body)
                command = match.group(1) if match else ""
                with self.lock:
                    # An <authenticate> body carries the password. Record the
                    # command and shape, never the credential itself.
                    safe = body
                    if command == "authenticate":
                        safe = "<authenticate>[redacted]</authenticate>"
                    self.requests.append({
                        "method": "GMP",
                        "path": command,
                        "query": "",
                        "body": safe,
                        "headers": {},
                    })
                    spec = self.default
                    for route in self.routes:
                        if route.matches(command, body):
                            spec = route.next_response()
                            break
                payload = self._body_for(spec)
                if payload:
                    conn.sendall(payload)
                if spec.get("close"):
                    return
        except (OSError, ssl.SSLError):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _accept_loop(self):
        while not self._stop:
            try:
                raw, _ = self._sock.accept()
            except OSError:
                return
            try:
                conn = self._ctx.wrap_socket(raw, server_side=True)
            except (OSError, ssl.SSLError):
                try:
                    raw.close()
                except OSError:
                    pass
                continue
            # Bounded, for the reason server.py's pool is: a thread per
            # accepted connection is unbounded by anything the scenario
            # controls, and a client that opens many at once can exhaust the
            # machine rather than fail the test.
            self._pool.submit(self._serve_conn, conn)

    def start(self):
        self._pool = ThreadPoolExecutor(max_workers=GMP_MAX_WORKERS)
        self._certdir = tempfile.mkdtemp(prefix="rz-gmp-tls-")
        cert, key = _self_signed(self._certdir)
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(cert, key)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(GMP_LISTEN_BACKLOG)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return "127.0.0.1", self._sock.getsockname()[1]

    def stop(self):
        self._stop = True
        if self._pool:
            self._pool.shutdown(wait=False)
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._certdir:
            import shutil
            shutil.rmtree(self._certdir, ignore_errors=True)

    def snapshot(self):
        with self.lock:
            return list(self.requests)
