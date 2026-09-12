import json
import urllib.request
import urllib.parse
import shutil
import ssl
import os

_USE_CURL = None
_CURL_PATH = None

# mTLS device identity (gap-closing): percorsi PEM impostati dall'agent.
# Mai trust-all: senza CA il TLS fallisce chiuso (urllib) o usa lo store
# di sistema (curl) — il server nega comunque senza certificato valido.
_CLIENT_CERT = None
_CLIENT_KEY = None


def set_client_cert(cert_path, key_path):
    """Certificato+chiave device per TLS mutuo (None per disabilitare)."""
    global _CLIENT_CERT, _CLIENT_KEY
    _CLIENT_CERT = cert_path
    _CLIENT_KEY = key_path


def _client_cert_files():
    if _CLIENT_CERT and _CLIENT_KEY and os.path.isfile(_CLIENT_CERT) and os.path.isfile(_CLIENT_KEY):
        return _CLIENT_CERT, _CLIENT_KEY
    return None, None

class Response:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text
    def json(self):
        return json.loads(self.text)

def _detect_curl():
    global _USE_CURL, _CURL_PATH
    path = shutil.which('curl.exe') or shutil.which('curl')
    if path:
        _CURL_PATH = path
        _USE_CURL = True
    else:
        _USE_CURL = False

def _urllib_request(method, url, json_data=None, headers=None, timeout=10):
    data = None
    if json_data is not None:
        data = json.dumps(json_data).encode('utf-8')
    req = urllib.request.Request(url, data=data, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if json_data is not None:
        req.add_header('Content-Type', 'application/json')
    ca_bundle = os.getenv("AEGIS_CA_BUNDLE")
    ctx = ssl.create_default_context(cafile=ca_bundle or None)
    cert, key = _client_cert_files()
    if cert and key:
        try:
            ctx.load_cert_chain(cert, key)
        except (ssl.SSLError, OSError) as e:
            raise Exception(f'Device identity illeggibile: {e}')
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read().decode('utf-8')
        return Response(resp.status, body)
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        return Response(e.code, body)
    except urllib.error.URLError as e:
        raise Exception(f'Request failed: {e.reason}')

def _curl_request(method, url, json_data=None, headers=None, timeout=10):
    import subprocess
    cmd = [_CURL_PATH, '-s', '-w', '%{http_code}', '-o', '-', '--max-time', str(timeout), '-X', method.upper()]
    ca_bundle = os.getenv("AEGIS_CA_BUNDLE")
    if ca_bundle and os.path.isfile(ca_bundle):
        cmd.extend(['--cacert', ca_bundle])
    cert, key = _client_cert_files()
    if cert and key:
        cmd.extend(['--cert', cert, '--key', key])
    for k, v in (headers or {}).items():
        cmd.extend(['-H', f'{k}: {v}'])
    if json_data is not None:
        cmd.extend(['-H', 'Content-Type: application/json', '-d', json.dumps(json_data)])
    cmd.append(url)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        output = result.stdout
        if len(output) < 3:
            raise Exception('curl produced no output')
        status = int(output[-3:])
        body = output[:-3]
        return Response(status, body)
    except subprocess.TimeoutExpired:
        raise Exception('Request timeout')

def request(method, url, json_data=None, headers=None, timeout=10):
    if _USE_CURL is None:
        _detect_curl()
    if _USE_CURL:
        try:
            return _curl_request(method, url, json_data, headers, timeout)
        except Exception:
            pass
    return _urllib_request(method, url, json_data, headers, timeout)

def get(url, headers=None, params=None, timeout=10):
    if params:
        qs = urllib.parse.urlencode(params)
        url = f'{url}?{qs}'
    return request('GET', url, headers=headers, timeout=timeout)

def post(url, json_data=None, headers=None, timeout=10):
    return request('POST', url, json_data=json_data, headers=headers, timeout=timeout)
