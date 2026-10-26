#!/usr/bin/env python3
"""The update emulator's model mirror (Phase 14 design §11.4): the loopback stand-in the gate
build's UpdateLoopback seam fetches from. It serves exactly what the real mirrors serve —
`/ghost/v1/<net>/current.ghrb` (200) and `/ghost/v1/<net>/apk/<sha256>` (206 with the matching
`Content-Range` on a `Range: bytes=a-b` request, §7.2's fixed 4 MiB steps) — over plain HTTP/1.1,
because the seam replaces the whole transport, the Tor stream included.

Never serves anything else: any other path is 404, any method but GET is 405, a directory
traversal is refused, and the body bytes are the files under --root, nothing generated.

Usage:
  python3 update-model-mirror.py --root <dir> [--host 127.0.0.1] [--port 8471]

<dir> layout:
  v1/<net>/current.ghrb          one bundle per network
  v1/<net>/apk/<sha256 hex>      the offered APK, named by its SHA-256
"""
import argparse
import http.server
import os
import re
import sys

APK_NAME = re.compile(r"^[0-9a-f]{64}$")
RANGE = re.compile(r"^bytes=(\d+)-(\d+)$")
NET = re.compile(r"^[a-z0-9_-]+$")


class ModelMirror(http.server.BaseHTTPRequestHandler):
    root = "."

    # The wire has no version, no user-agent, no locale (RQ-D13): the model logs nothing but
    # the test's own diagnostics on stderr, and answers every request the same for any headers.
    def log_message(self, fmt, *args):
        sys.stderr.write("model-mirror: %s\n" % (fmt % args))

    def do_GET(self):
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        parts = [p for p in path.split("/") if p]
        # The fixed paths of §7.2 carry the /ghost prefix the real mirrors serve under; the
        # layout under --root is the same tree (v1/<net>/...), so strip the prefix.
        if parts and parts[0] == "ghost":
            parts = parts[1:]
        # Normalise: /v1/<net>/current.ghrb or /v1/<net>/apk/<sha>
        if len(parts) == 3 and parts[0] == "v1" and NET.match(parts[1]) and parts[2] == "current.ghrb":
            rel = os.path.join("v1", parts[1], "current.ghrb")
        elif len(parts) == 4 and parts[0] == "v1" and NET.match(parts[1]) and parts[2] == "apk" and APK_NAME.match(parts[3]):
            rel = os.path.join("v1", parts[1], "apk", parts[3])
        else:
            self.send_error(404)
            return
        full = os.path.realpath(os.path.join(self.root, rel))
        root_real = os.path.realpath(self.root)
        if not full.startswith(root_real + os.sep) or not os.path.isfile(full):
            self.send_error(404)
            return
        size = os.path.getsize(full)
        header = self.headers.get("Range")
        if rel.endswith("current.ghrb"):
            # The bundle answers 200 with no range handling at all.
            if header:
                self.send_error(400)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(size))
            self.end_headers()
            self._body(full, 0, size)
            return
        if not header:
            self.send_response(200)
            self.send_header("Content-Length", str(size))
            self.end_headers()
            self._body(full, 0, size)
            return
        m = RANGE.match(header.strip())
        if not m:
            self.send_error(400)
            return
        start, end = int(m.group(1)), int(m.group(2))
        if start > end or start >= size:
            self.send_error(416)
            return
        end = min(end, size - 1)
        self.send_response(206)
        self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.send_header("Content-Length", str(end - start + 1))
        self.end_headers()
        self._body(full, start, end - start + 1)

    def _body(self, full, start, length):
        with open(full, "rb") as f:
            f.seek(start)
            remaining = length
            while remaining > 0:
                chunk = f.read(min(65536, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def do_POST(self):
        self.send_error(405)

    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8471)
    a = ap.parse_args()
    ModelMirror.root = os.path.realpath(a.root)
    server = http.server.ThreadingHTTPServer((a.host, a.port), ModelMirror)
    sys.stderr.write("model-mirror: serving %s on %s:%d\n" % (ModelMirror.root, a.host, a.port))
    server.serve_forever()


if __name__ == "__main__":
    main()
