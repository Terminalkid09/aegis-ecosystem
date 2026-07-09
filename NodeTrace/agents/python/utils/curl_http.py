import json
import urllib.request
import urllib.parse
import shutil
import ssl

_USE_CURL = None
_CURL_PATH = None

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
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
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
