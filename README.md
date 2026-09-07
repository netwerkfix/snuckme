# snuck.me — Python 3 port

This fork replaces the original Node.js/Express backend with Python 3 and
FastAPI. It retrieves the TLS certificate presented to the server and returns
the fields used by the original snuck.me interface.

## Run locally

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip git wget curl nano -y

git clone https://github.com/netwerkfix/snuckme.git
cd snuckme
git pull origin master

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt

uvicorn app:app --host 0.0.0.0 --port 8000

curl http://127.0.0.1:8000/health

## Certificate API testen ##
curl -s -X POST http://127.0.0.1:8000/api/certificate \
  -H "Content-Type: application/json" \
  -d '{"url":"google.com"}' | python3 -m json.tool

## Je moet onder andere dit terugkrijgen:
 {
  "success": true,
  "hostname": "google.com",
  "port": 443
}
##

```

Open <http://127.0.0.1:8000>. API documentation is available at
<http://127.0.0.1:8000/docs>.

## Docker

```bash
sudo docker build -t snuckme-python .
sudo docker run --rm -p 8000:8000 snuckme-python

# Test it ##
sudo curl http://127.0.0.1:8000/health
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
