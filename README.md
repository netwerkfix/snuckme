# snuck.me — Python 3 port

This fork replaces the original Node.js/Express backend with Python 3 and
FastAPI. It retrieves the TLS certificate presented to the server and returns
the fields used by the original snuck.me interface.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

Open <http://127.0.0.1:8000>. API documentation is available at
<http://127.0.0.1:8000/docs>.

## Docker

```bash
docker build -t snuckme-python .
docker run --rm -p 8000:8000 snuckme-python
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8000` | Port used by `python app.py` |
| `SNUCKME_TLS_TIMEOUT` | `5` | TLS connection timeout in seconds (0.5–20) |
| `SNUCKME_ALLOW_PRIVATE_TARGETS` | `false` | Allow private/loopback targets; use only in trusted networks |

Private, loopback, link-local, and reserved destinations are blocked by
default to prevent the public API from being used for server-side request
forgery (SSRF).

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The original MIT license and attribution are retained.
