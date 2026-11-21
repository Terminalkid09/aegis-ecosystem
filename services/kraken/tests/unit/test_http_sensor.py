from honeypot.sensors.http_sensor import HTTPSensor


def test_parse_request_captures_method_path_headers_and_body():
    sensor = HTTPSensor()
    raw = (
        "POST /login HTTP/1.1\r\n"
        "Host: portal.acme.local\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Content-Length: 13\r\n\r\n"
        "user=admin&x=1"
    )
    method, path, headers, body = sensor._parse_request(raw)
    assert method == "POST"
    assert path == "/login"
    assert headers["Host"] == "portal.acme.local"
    assert body == b"user=admin&x=1"


def test_vhost_returns_portal_instead_of_default_page():
    sensor = HTTPSensor()
    status, headers, body = sensor._response("GET", "/", {"Host": "portal.acme.local"})
    assert status == 200
    assert "Acme Intranet" in body.decode()
    assert headers["Content-Type"].startswith("text/html")


def test_recon_paths_do_not_all_return_200():
    sensor = HTTPSensor()
    assert sensor._response("GET", "/.env", {})[0] == 404
    assert sensor._response("GET", "/server-status", {})[0] == 403
    assert sensor._response("GET", "/owa/", {})[0] == 200
    assert sensor._response("GET", "/does-not-exist", {})[0] == 404
