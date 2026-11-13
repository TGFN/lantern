<p align="center">
  <img src="https://gor-mez8.onrender.com/render.gif?text=LANTERN&effect=glitch&font=monobold&w=680&h=110&size=72&c1=e2e8f0&bg=0a0a0f&fps=16&dur=3&seed=42" alt="LANTERN">
</p>

<p align="center">
  <img src="https://gor-mez8.onrender.com/render.gif?text=A+better+python+-m+http.server&effect=vhs&font=mono&w=620&h=48&size=22&c1=94a3b8&bg=0a0a0f&fps=12&dur=2.5&seed=7" alt="tagline">
</p>

<br>

**Modern LAN file server** — Range requests, pretty directory listing, Basic Auth, uploads, TLS.  
**Zero dependencies.** Pure Python 3.8+ stdlib.

---

### Features

| Feature | Description |
|--------|-------------|
| **Range requests** | Full `206 Partial Content` support → video / audio seeking works |
| **Keep-alive + caching** | HTTP/1.1, ETag, `Last-Modified`, proper `304` |
| **Pretty listing** | Dark theme directory listing with breadcrumbs |
| **Security** | Path traversal & symlink escape protection |
| **Basic Auth** | Optional `--user` / `--pass` |
| **Uploads** | Optional `PUT` support with `--upload` |
| **TLS** | Optional HTTPS via `--cert` / `--key` |
| **CORS** | Optional `--cors` |
| **Health** | `/_ping` and `/_info` JSON endpoint |
| **Zero deps** | Pure stdlib — runs anywhere Python runs |

---

### Quick Start

```bash
# Serve current directory on 0.0.0.0:8000
python lantern.py

# Custom directory + port
python lantern.py --dir \~/Videos -p 8080

# With authentication + upload
python lantern.py --user admin --pass secret --upload

# HTTPS
python lantern.py --cert cert.pem --key key.pem -p 443
