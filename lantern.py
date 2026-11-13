#!/usr/bin/env python3
"""
lantern.py — LAN file server. A better `python -m http.server`.

Features
  • Range requests (206) → <video>/<audio> seeking works
  • HTTP/1.1 keep-alive, ETag + Last-Modified (304)
  • Pretty dark directory listing with breadcrumbs
  • Path traversal / symlink-escape protection
  • Optional Basic Auth  (--user / --pass)
  • Optional PUT uploads (--upload)
  • Optional TLS         (--cert / --key)
  • Optional CORS        (--cors)
  • /_info JSON endpoint, /_ping health check
  • Prints all LAN URLs on start (works with DuckDNS → LAN)
  • Zero dependencies — pure stdlib, runs anywhere Python 3.8+ runs

Usage
  python lantern.py                              # serve cwd on 0.0.0.0:8000
  python lantern.py --dir ~/Videos -p 8080
  python lantern.py --user admin --pass secret --upload
  python lantern.py --cert cert.pem --key key.pem -p 443
"""

import argparse
import base64
import email.utils
import html
import json
import mimetypes
import os
import re
import socket
import ssl
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlsplit

CHUNK = 64 * 1024
VERSION = "1.0"

BANNER = r"""
  _                           _
 | |    __ _ _ __  _ __   ___| |_
 | |   / _` | '_ \| '_ \ / _ \ __|
 | |__| (_| | | | | | | |  __/ |_
 |_____\__,_|_| |_|_| |_|\___|\__|
        LAN file server  v{version}
""".format(version=VERSION)

EXTRA_MIME = {
    ".mp4": "video/mp4", ".webm": "video/webm", ".mkv": "video/x-matroska",
    ".mov": "video/quicktime", ".m4v": "video/x-m4v",
    ".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".flac": "audio/flac",
    ".wav": "audio/wav", ".ogg": "audio/ogg", ".opus": "audio/opus",
    ".m3u8": "application/vnd.apple.mpegurl",
    ".webp": "image/webp", ".avif": "image/avif", ".svg": "image/svg+xml",
    ".wasm": "application/wasm", ".json": "application/json",
    ".js": "application/javascript", ".mjs": "application/javascript",
    ".css": "text/css", ".md": "text/markdown",
    ".toml": "application/toml", ".yaml": "application/yaml",
    ".yml": "application/yaml",
}


def mime_for(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in EXTRA_MIME:
        return EXTRA_MIME[ext]
    guess, _ = mimetypes.guess_type(path)
    return guess or "application/octet-stream"


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def lan_ips() -> list:
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    ips.discard("127.0.0.1")
    return sorted(ips)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"Lantern/{VERSION}"
    sys_version = ""

    # injected via make_server()
    root = "."
    allow_upload = False
    max_upload = 0
    auth = None
    cors = False
    hide_dot = False
    index_names = ("index.html", "index.htm")

    # ---------- logging ----------
    def log_message(self, fmt, *args):
        sys.stderr.write(
            f"{self.log_date_time_string()} [{self.client_address[0]}] {fmt % args}\n"
        )

    # ---------- helpers ----------
    def _send_common_headers(self):
        if self.cors:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, HEAD, PUT, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header(
                "Access-Control-Expose-Headers",
                "Content-Range, Content-Length, Accept-Ranges, ETag, Last-Modified",
            )

    def _resolve_path(self, url_path: str):
        p = unquote(url_path).split("?", 1)[0].split("#", 1)[0].replace("\\", "/")
        norm = os.path.normpath("/" + p).lstrip("/")
        full = os.path.realpath(os.path.join(self.root, norm))
        root_real = os.path.realpath(self.root)
        if full != root_real and not full.startswith(root_real + os.sep):
            return None, None
        return full, "/" + norm.replace(os.sep, "/")

    def _check_auth(self) -> bool:
        if not self.auth:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return self._challenge_auth()
        try:
            decoded = base64.b64decode(header[6:]).decode("utf-8")
            user, _, pw = decoded.partition(":")
        except Exception:
            return self._challenge_auth()
        if (user, pw) == self.auth:
            return True
        return self._challenge_auth()

    def _challenge_auth(self):
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="lantern"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    # ---------- HTTP methods ----------
    def do_OPTIONS(self):
        if not self.cors:
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_common_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self._serve(head_only=True)

    def do_GET(self):
        self._serve(head_only=False)

    def do_PUT(self):
        if not self.allow_upload:
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, "Upload disabled")
            return
        if not self._check_auth():
            return
        self._handle_put()

    # ---------- core ----------
    def _serve(self, head_only: bool):
        if not self._check_auth():
            return

        parts = urlsplit(self.path)
        path = parts.path

        if path == "/_info":
            return self._send_info()
        if path == "/_ping":
            body = b"ok"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self._send_common_headers()
            self.end_headers()
            if not head_only:
                self.wfile.write(body)
            return

        fs_path, url_path = self._resolve_path(path)
        if fs_path is None:
            self.send_error(HTTPStatus.FORBIDDEN, "Forbidden path")
            return
        if not os.path.exists(fs_path):
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        if os.path.isdir(fs_path):
            if not path.endswith("/"):
                loc = path + "/" + (f"?{parts.query}" if parts.query else "")
                self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                self.send_header("Location", loc)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            for idx in self.index_names:
                cand = os.path.join(fs_path, idx)
                if os.path.isfile(cand):
                    return self._serve_file(cand, head_only)
            return self._list_dir(fs_path, url_path, head_only)

        return self._serve_file(fs_path, head_only)

    def _serve_file(self, fs_path: str, head_only: bool):
        try:
            st = os.stat(fs_path)
        except OSError as e:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))
            return
        size = st.st_size
        mtime = st.st_mtime
        etag = '"%x-%x"' % (int(mtime), size)
        last_modified = email.utils.formatdate(mtime, usegmt=True)

        # If-None-Match
        inm = self.headers.get("If-None-Match")
        if inm and etag in [t.strip() for t in inm.split(",")]:
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self.send_header("ETag", etag)
            self.send_header("Last-Modified", last_modified)
            self.send_header("Content-Length", "0")
            self._send_common_headers()
            self.end_headers()
            return

        # If-Modified-Since
        ims = self.headers.get("If-Modified-Since")
        if ims:
            try:
                dt = email.utils.parsedate_to_datetime(ims)
                if dt and int(mtime) <= int(dt.timestamp()):
                    self.send_response(HTTPStatus.NOT_MODIFIED)
                    self.send_header("ETag", etag)
                    self.send_header("Last-Modified", last_modified)
                    self.send_header("Content-Length", "0")
                    self._send_common_headers()
                    self.end_headers()
                    return
            except Exception:
                pass

        # Range
        start, end, partial = 0, size - 1, False
        range_header = self.headers.get("Range")
        if range_header:
            parsed = self._parse_range(range_header, size)
            if parsed is None:
                self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                self.send_header("Content-Range", f"bytes */{size}")
                self.send_header("Content-Length", "0")
                self._send_common_headers()
                self.end_headers()
                return
            start, end = parsed
            partial = True

        length = max(0, end - start + 1)
        status = HTTPStatus.PARTIAL_CONTENT if partial else HTTPStatus.OK

        self.send_response(status)
        self.send_header("Content-Type", mime_for(fs_path))
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("ETag", etag)
        self.send_header("Last-Modified", last_modified)
        if partial:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self._send_common_headers()
        self.end_headers()

        if head_only or length == 0:
            return

        try:
            with open(fs_path, "rb") as f:
                f.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = f.read(min(CHUNK, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _parse_range(self, header: str, size: int):
        m = re.match(r"bytes=(\d*)-(\d*)$", header.strip())
        if not m:
            return None
        a, b = m.group(1), m.group(2)
        if not a and not b:
            return None
        if not a:                              # bytes=-N  (last N bytes)
            n = int(b)
            if n <= 0:
                return None
            start, end = max(0, size - n), size - 1
        elif not b:                            # bytes=N-
            start, end = int(a), size - 1
        else:                                  # bytes=N-M
            start, end = int(a), int(b)
        if start > end or start >= size:
            return None
        return (start, min(end, size - 1))

    # ---------- directory listing ----------
    def _list_dir(self, fs_path: str, url_path: str, head_only: bool):
        try:
            names = os.listdir(fs_path)
        except OSError as e:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))
            return

        if self.hide_dot:
            names = [n for n in names if not n.startswith(".")]

        dirs, files = [], []
        for name in names:
            full = os.path.join(fs_path, name)
            try:
                st = os.stat(full)
            except OSError:
                continue
            item = {"name": name, "size": st.st_size,
                    "mtime": st.st_mtime, "is_dir": os.path.isdir(full)}
            (dirs if item["is_dir"] else files).append(item)
        dirs.sort(key=lambda x: x["name"].lower())
        files.sort(key=lambda x: x["name"].lower())

        def esc(s):
            return html.escape(s, quote=True)

        rows = []
        if url_path != "/":
            rows.append(
                '<tr><td class="icon">⬆</td>'
                '<td><a href="../">Parent directory</a></td>'
                '<td></td><td></td></tr>'
            )
        for it in dirs:
            name = it["name"] + "/"
            rows.append(
                f'<tr><td class="icon">📁</td>'
                f'<td><a href="{quote(name)}">{esc(name)}</a></td>'
                f'<td class="size">—</td>'
                f'<td class="mtime">{time.strftime("%Y-%m-%d %H:%M", time.localtime(it["mtime"]))}</td></tr>'
            )
        for it in files:
            name = it["name"]
            rows.append(
                f'<tr><td class="icon">📄</td>'
                f'<td><a href="{quote(name)}">{esc(name)}</a></td>'
                f'<td class="size">{human_size(it["size"])}</td>'
                f'<td class="mtime">{time.strftime("%Y-%m-%d %H:%M", time.localtime(it["mtime"]))}</td></tr>'
            )

        crumbs, acc = ['<a href="/">root</a>'], "/"
        for p in [x for x in url_path.split("/") if x]:
            acc += quote(p) + "/"
            crumbs.append(f'<a href="{acc}">{esc(p)}</a>')
        crumb_html = " / ".join(crumbs)

        page = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Index of {esc(url_path)} — lantern</title>
<style>
:root{{--bg:#0b0b0d;--fg:#d6d3d1;--pink:#ff2e88;--cyan:#00e5ff;--dim:#8a8a8a;--border:rgba(255,255,255,.08)}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);
 font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;padding:32px 20px;line-height:1.6}}
.wrap{{max-width:1000px;margin:0 auto}}
h1{{font-size:22px;margin:0 0 4px;letter-spacing:.03em}}
h1 span{{color:var(--pink)}}
.crumbs{{font-size:13px;opacity:.7;margin-bottom:18px}}
.crumbs a{{color:var(--cyan);text-decoration:none}}
.crumbs a:hover{{text-decoration:underline}}
table{{width:100%;border-collapse:collapse;font-size:13.5px}}
th{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);
 font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--cyan);font-weight:600}}
td{{padding:8px 10px;border-bottom:1px solid var(--border)}}
tr:hover td{{background:rgba(255,255,255,.03)}}
a{{color:var(--fg);text-decoration:none}}a:hover{{color:var(--pink)}}
.icon{{width:32px;text-align:center;opacity:.7}}
.size,.mtime{{color:var(--dim);font-variant-numeric:tabular-nums;white-space:nowrap}}
.mtime{{font-size:12px}}
footer{{margin-top:24px;font-size:11px;opacity:.35;letter-spacing:.15em;text-transform:uppercase}}
</style></head><body><div class="wrap">
<h1>Index of <span>{esc(url_path)}</span></h1>
<div class="crumbs">{crumb_html}</div>
<table><thead><tr><th></th><th>Name</th><th>Size</th><th>Modified</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<footer>lantern · {self.server.server_address[0]}:{self.server.server_address[1]}</footer>
</div></body></html>"""

        body = page.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_common_headers()
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    # ---------- PUT upload ----------
    def _handle_put(self):
        fs_path, _ = self._resolve_path(urlsplit(self.path).path)
        if fs_path is None:
            self.send_error(HTTPStatus.FORBIDDEN, "Forbidden path")
            return
        if not os.path.isdir(os.path.dirname(fs_path)):
            self.send_error(HTTPStatus.CONFLICT, "Parent directory does not exist")
            return

        length = self.headers.get("Content-Length")
        if length is None:
            self.send_error(HTTPStatus.LENGTH_REQUIRED)
            return
        try:
            remaining = int(length)
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST, "Bad Content-Length")
            return
        if self.max_upload and remaining > self.max_upload:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                            f"Upload exceeds {human_size(self.max_upload)}")
            return

        tmp = fs_path + ".part"
        try:
            with open(tmp, "wb") as f:
                while remaining > 0:
                    chunk = self.rfile.read(min(CHUNK, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)
            os.replace(tmp, fs_path)
        except Exception as e:
            try:
                os.remove(tmp)
            except OSError:
                pass
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))
            return

        self.send_response(HTTPStatus.CREATED)
        self.send_header("Content-Length", "0")
        self._send_common_headers()
        self.end_headers()

    # ---------- info ----------
    def _send_info(self):
        payload = {
            "server": self.server_version,
            "root": os.path.abspath(self.root),
            "bind": f"{self.server.server_address[0]}:{self.server.server_address[1]}",
            "auth": bool(self.auth),
            "upload": self.allow_upload,
            "cors": self.cors,
            "time": int(time.time()),
        }
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._send_common_headers()
        self.end_headers()
        self.wfile.write(body)


def make_server(bind: str, port: int, root: str, *, allow_upload=False,
                max_upload=0, auth=None, cors=False, hide_dot=False,
                certfile=None, keyfile=None):
    Bound = type("BoundHandler", (Handler,), {
        "root": os.path.abspath(root),
        "allow_upload": allow_upload,
        "max_upload": max_upload,
        "auth": auth,
        "cors": cors,
        "hide_dot": hide_dot,
    })
    srv = ThreadingHTTPServer((bind, port), Bound)
    srv.daemon_threads = True
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        srv.scheme = "https"
    else:
        srv.scheme = "http"
    return srv


def main():
    p = argparse.ArgumentParser(
        prog="lantern.py",
        description="lantern — a better `python -m http.server`",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--dir", default=".", help="directory to serve")
    p.add_argument("--bind", default="0.0.0.0", help="bind address")
    p.add_argument("-p", "--port", type=int, default=8000, help="port")
    p.add_argument("--user", help="basic auth username")
    p.add_argument("--pass", dest="password", help="basic auth password")
    p.add_argument("--upload", action="store_true", help="enable PUT uploads")
    p.add_argument("--max-upload", type=int, default=0,
                   help="max upload size in bytes (0 = unlimited)")
    p.add_argument("--cors", action="store_true", help="add CORS headers")
    p.add_argument("--hide-dot", action="store_true", help="hide dotfiles")
    p.add_argument("--cert", help="TLS certificate file")
    p.add_argument("--key", help="TLS key file")
    p.add_argument("--no-banner", action="store_true", help="hide startup banner")
    args = p.parse_args()

    if args.user and not args.password:
        p.error("--user requires --pass")

    if not args.no_banner:
        print(BANNER)

    try:
        srv = make_server(
            args.bind, args.port, args.dir,
            allow_upload=args.upload, max_upload=args.max_upload,
            auth=(args.user, args.password) if args.user else None,
            cors=args.cors, hide_dot=args.hide_dot,
            certfile=args.cert, keyfile=args.key,
        )
    except OSError as e:
        print(f"error: cannot bind {args.bind}:{args.port} — {e}", file=sys.stderr)
        sys.exit(1)

    scheme = srv.scheme
    print("=" * 62)
    print(f"serving: {os.path.abspath(args.dir)}")
    print(f"local:   {scheme}://127.0.0.1:{args.port}/")
    for ip in lan_ips():
        print(f"LAN:     {scheme}://{ip}:{args.port}/")
    flags = [k for k, v in [
        ("auth", bool(args.user)), ("upload", args.upload),
        ("cors", args.cors), ("tls", bool(args.cert)),
    ] if v]
    if flags:
        print(f"flags:   {', '.join(flags)}")
    print(f"press Ctrl+C to stop")
    print("=" * 62)

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down...")
        srv.shutdown()


if __name__ == "__main__":
    main()
