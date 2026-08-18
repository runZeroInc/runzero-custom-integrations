"""Declarative fixture server for custom integration tests.

The scanner's own `--validate` mode answers every request from three built-in
heuristics and returns empty collections, so it can prove a script wires up and
does not abort but never that it parses a row correctly. This server replaces
those heuristics with per-integration scenario files, which is what makes the
call *sequence* testable: a route holds an ordered list of responses, so page 2
can differ from page 1, a token can expire mid-run, and a job can report
"running" before it reports "done".

A scenario is JSON. See tests/README.md for the full schema.
"""

import base64
import http.server
import json
import os
import re
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor


# http.server.ThreadingHTTPServer spawned one unbounded thread per connection,
# and with HTTP/1.1 keep-alive each thread stayed pinned for the life of the
# connection rather than the life of a request. A scanner opening many
# connections at once, times the several fixture servers a parallel run keeps
# up, was enough live threads to take the machine down.
#
# Two things changed. The server is a pool, so MAX_WORKERS is a hard ceiling
# rather than "however many connections arrive"; and every response closes its
# connection (see Handler.close_connection), so a worker is held for one request
# instead of one session. ThreadPoolExecutor also creates threads lazily, so
# this number is a cap, not an allocation -- the pool only grows to whatever is
# genuinely concurrent, which for these scenarios is a handful.
#
# Keep the per-request close. Without it a bounded pool fills with idle
# keep-alive connections, later connections are accepted but never serviced, and
# the scanner waits on a reply that cannot come -- the run deadlocks instead of
# failing. If a scenario hangs, suspect that before touching these numbers.
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "1000"))
# Backstop for a client that opens a connection and then says nothing.
CONN_TIMEOUT = float(os.environ.get("CONN_TIMEOUT", "10"))


class PooledHTTPServer(http.server.HTTPServer):
    """HTTPServer bounded by a fixed worker pool, not a thread per connection."""

    # socketserver defaults this to 5. Because every response closes its
    # connection, a scenario that makes thousands of requests also makes
    # thousands of connections, and a backlog of 5 overflows: the kernel
    # refuses the excess, the scanner retries, and the request counts these
    # scenarios assert on drift upward. The backlog is a queue length, not
    # threads -- raising it does not reintroduce the thread exhaustion.
    request_queue_size = int(os.environ.get("LISTEN_BACKLOG", "1000"))

    def __init__(self, *args, **kwargs):
        http.server.HTTPServer.__init__(self, *args, **kwargs)
        self._pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def process_request(self, request, client_address):
        self._pool.submit(self._run, request, client_address)

    def _run(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    def handle_error(self, request, client_address):
        # A scanner that got its answer and hung up mid-write is normal here;
        # the default handler prints a traceback per occurrence and buries the
        # scenario's real failure.
        pass

    def server_close(self):
        http.server.HTTPServer.server_close(self)
        self._pool.shutdown(wait=False)


class Route(object):
    """One matcher plus the ordered responses it hands back."""

    def __init__(self, spec):
        self.name = spec.get("name", "")
        match = spec.get("match", {})
        self.method = (match.get("method") or "").upper()
        self.path = match.get("path")
        self.path_prefix = match.get("path_prefix")
        self.path_regex = re.compile(match.get("path_regex")) if match.get("path_regex") else None
        self.query_contains = match.get("query_contains")
        self.body_contains = match.get("body_contains")
        # {"header": {"aw-tenant-code": "fixture-tenant"}} routes on a vendor
        # header; a value of "" matches on presence alone.
        self.header = {k.lower(): v for k, v in (match.get("header") or {}).items()}
        self.responses = spec.get("responses") or [{}]
        # repeat_last keeps a steady state after the scripted turns are used up,
        # which is what a well-behaved paginator sees at the end of a walk.
        # empty and error let a scenario assert the opposite.
        self.when_exhausted = spec.get("when_exhausted", "repeat_last")
        self.calls = 0

    def matches(self, method, path, query, body, headers):
        if self.method and self.method != method:
            return False
        if self.path is not None and self.path != path:
            return False
        if self.path_prefix is not None and not path.startswith(self.path_prefix):
            return False
        if self.path_regex is not None and not self.path_regex.search(path):
            return False
        if self.query_contains is not None and self.query_contains not in query:
            return False
        if self.body_contains is not None and self.body_contains not in body:
            return False
        for name, want in self.header.items():
            got = headers.get(name)
            if got is None or (want and want not in got):
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
            return {"status": 200, "json": []}
        return {"status": 500, "text": "fixture route exhausted"}


class FixtureServer(object):
    """Serves one scenario and records every request it received."""

    def __init__(self, scenario):
        self.routes = [Route(r) for r in scenario.get("routes", [])]
        self.default = scenario.get("default_response", {"status": 404, "text": "no fixture route"})
        self.requests = []
        self.lock = threading.Lock()
        self._httpd = None
        self._thread = None

    def handle(self, handler):
        parsed = urllib.parse.urlparse(handler.path)
        length = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(length).decode("utf-8", "replace") if length else ""
        method = handler.command.upper()

        with self.lock:
            self.requests.append({
                "method": method,
                "path": parsed.path,
                "query": parsed.query,
                "body": body,
                "authorization": handler.headers.get("Authorization") or "",
                "cookie": handler.headers.get("Cookie") or "",
                # Every header, lower-cased, so an integration that authenticates
                # with a vendor-specific header (aw-tenant-code, x-risk-token,
                # x-api-key) can be both routed on and asserted against.
                "headers": {k.lower(): v for k, v in handler.headers.items()},
            })
            spec = self.default
            for route in self.routes:
                if route.matches(method, parsed.path, parsed.query, body, self.requests[-1]["headers"]):
                    spec = route.next_response()
                    break

        status = spec.get("status", 200)
        headers = spec.get("headers", {})
        if "json" in spec:
            payload = json.dumps(spec["json"]).encode()
            content_type = "application/json"
        elif "body_base64" in spec:
            # A binary body. `text` is UTF-8 encoded, which mangles any byte
            # above 0x7f, so a gzip member (magic 1f 8b) cannot be expressed
            # that way at all. Integrations that download compressed scan data
            # -- runzero-task-sync decompresses what /org/tasks/<id>/data
            # returns -- are untestable without this.
            payload = base64.b64decode(spec["body_base64"])
            content_type = "application/octet-stream"
        else:
            payload = (spec.get("text") or "").encode()
            content_type = "text/plain"
        content_type = headers.get("Content-Type", content_type)

        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(payload)))
        # Announce the close the handler is going to perform anyway. Without
        # this the client sees an HTTP/1.1 response with no Connection header,
        # assumes the socket is reusable, pools it, and then finds it shut when
        # it sends the next request -- at which point Go's transport silently
        # RETRIES the request. That inflates the request counts these scenarios
        # assert on (jamf/page-ceiling saw 4040 instead of 4001).
        handler.send_header("Connection", "close")
        for key, value in headers.items():
            if key.lower() != "content-type":
                handler.send_header(key, value)
        handler.end_headers()
        if method != "HEAD":
            handler.wfile.write(payload)

    def start(self):
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            # HTTP/1.1 so responses carry the Content-Length semantics the
            # scanner expects, but every response also closes the connection:
            # that is what keeps one pooled worker per *request* rather than
            # per connection. Costs a reconnect per request, which is free
            # against a loopback fixture server.
            protocol_version = "HTTP/1.1"
            timeout = CONN_TIMEOUT
            close_connection = True

            def log_message(self, *args):
                pass

            def _dispatch(self):
                server.handle(self)
                self.close_connection = True

            do_GET = _dispatch
            do_POST = _dispatch
            do_PUT = _dispatch
            do_PATCH = _dispatch
            do_DELETE = _dispatch
            do_HEAD = _dispatch

        self._httpd = PooledHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return "http://127.0.0.1:%d" % self._httpd.server_address[1]

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()

    def snapshot(self):
        with self.lock:
            return list(self.requests)
