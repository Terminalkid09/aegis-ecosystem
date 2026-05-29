"""
Aegis-Ecosystem Communication & Configuration Verification Script

This script validates all components of the Aegis EDR ecosystem:
- Environment configuration (.env)
- Docker services and networking
- API endpoints and authentication
- Event flow and data persistence
"""

import os
import sys
import json
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Tuple, List

class Colors:
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    WARN = '\033[93m'
    OKBLUE = '\033[94m'
    RESET = '\033[0m'

def check(condition: bool, message: str) -> bool:
    symbol = f"{Colors.OKGREEN}✓{Colors.RESET}" if condition else f"{Colors.FAIL}✗{Colors.RESET}"
    status = f"{Colors.OKGREEN}OK{Colors.RESET}" if condition else f"{Colors.FAIL}FAILED{Colors.RESET}"
    print(f"{symbol} {message:<50} [{status}]")
    return condition

def warn(message: str):
    print(f"{Colors.WARN}⚠{Colors.RESET} {message}")

def info(message: str):
    print(f"{Colors.OKBLUE}ℹ{Colors.RESET} {message}")

def section(title: str):
    print(f"\n{Colors.OKBLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.OKBLUE}  {title}{Colors.RESET}")
    print(f"{Colors.OKBLUE}{'='*60}{Colors.RESET}\n")

def load_env() -> Dict[str, str]:
    """Load .env file"""
    env = {}
    env_file = Path(".env")
    
    if not env_file.exists():
        return env
    
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                env[key.strip()] = value.strip()
    
    return env

def check_http_endpoint(url: str, headers: Dict = None) -> Tuple[bool, str]:
    """Check if HTTP endpoint is accessible"""
    try:
        req = urllib.request.Request(url)
        if headers:
            for key, value in headers.items():
                req.add_header(key, value)
        response = urllib.request.urlopen(req, timeout=5)
        return True, f"HTTP {response.status}"
    except urllib.error.URLError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def run_command(cmd: List[str]) -> Tuple[bool, str]:
    """Run shell command"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0, result.stdout.strip() + result.stderr.strip()
    except Exception as e:
        return False, str(e)

def main():
    print(f"\n{Colors.OKBLUE}Aegis EDR Ecosystem Verification{Colors.RESET}\n")
    
    # === SECTION 1: Environment Configuration ===
    section("1. Environment Configuration")
    
    env = load_env()
    
    checks_passed = 0
    checks_total = 0
    
    required_vars = {
        'AEGIS_API_KEY': 'API Key for authentication',
        'AEGIS_AGENT_ID': 'Unique agent identifier',
        'POSTGRES_DB': 'PostgreSQL database name',
        'POSTGRES_USER': 'PostgreSQL user',
        'POSTGRES_PASSWORD': 'PostgreSQL password',
    }
    
    for var, desc in required_vars.items():
        checks_total += 1
        value = env.get(var, '')
        is_ok = len(value) > 0
        if check(is_ok, f"{var:<30} {desc}"):
            checks_passed += 1
            if var == 'AEGIS_API_KEY':
                info(f"  API Key length: {len(value)} chars")
    
    # === SECTION 2: Docker Services ===
    section("2. Docker Services")
    
    # Check if docker is available
    checks_total += 1
    docker_ok, _ = run_command(['docker', '--version'])
    if check(docker_ok, "Docker daemon"):
        checks_passed += 1
        
        # Check running containers
        checks_total += 1
        containers_ok, output = run_command(['docker-compose', 'ps', '--format', 'table'])
        
        if containers_ok:
            running = output.count('running') if output else 0
            expected = 5  # postgres, redis, link, brain, guard
            if check(running >= expected, f"Running containers (found {running}, expected {expected})"):
                checks_passed += 1
            else:
                warn(f"Only {running} services running. Expected at least {expected}")
        else:
            check(False, "Docker Compose")
    else:
        check(False, "Docker daemon")
    
    # === SECTION 3: Service Health ===
    section("3. Service Health Checks")
    
    api_key = env.get('AEGIS_API_KEY', 'aegis_secret_key_123')
    headers = {'X-Api-Key': api_key}
    
    services = {
        'aegis-link Health': 'http://localhost:8088/api/v1/health',
        'aegis-brain Health': 'http://localhost:8000/',
    }
    
    for service_name, url in services.items():
        checks_total += 1
        ok, msg = check_http_endpoint(url, headers)
        if check(ok, service_name):
            checks_passed += 1
            info(f"  {msg}")
        else:
            warn(f"  {msg}")
    
    # === SECTION 4: Database Connectivity ===
    section("4. Database Connectivity")
    
    checks_total += 1
    if check(env.get('POSTGRES_USER'), "PostgreSQL credentials"):
        checks_passed += 1
        
        pg_user = env.get('POSTGRES_USER', 'aegis_user')
        pg_pass = env.get('POSTGRES_PASSWORD', '')
        pg_host = env.get('POSTGRES_HOST', 'localhost')
        pg_port = env.get('POSTGRES_PORT', '5432')
        pg_db = env.get('POSTGRES_DB', 'aegis')
        
        checks_total += 1
        psql_cmd = [
            'docker', 'exec', 'aegis-postgres',
            'psql', '-U', pg_user, '-d', pg_db,
            '-c', 'SELECT COUNT(*) as agents FROM agents;'
        ]
        psql_ok, psql_output = run_command(psql_cmd)
        if check(psql_ok, "Query Postgres for agents"):
            checks_passed += 1
            info(f"  {psql_output}")
    
    # === SECTION 5: Redis Queue Status ===
    section("5. Redis Queue Status")
    
    redis_commands = {
        'Events Queue': ['docker', 'exec', 'aegis-redis', 'redis-cli', 'LLEN', 'aegis:events'],
        'Commands Queues': ['docker', 'exec', 'aegis-redis', 'redis-cli', 'KEYS', 'aegis:commands:*'],
    }
    
    for queue_name, cmd in redis_commands.items():
        checks_total += 1
        ok, output = run_command(cmd)
        if check(ok, f"Redis {queue_name}"):
            checks_passed += 1
            info(f"  {output}")
    
    # === SECTION 6: API Endpoints ===
    section("6. API Endpoints")
    
    endpoints = {
        'List Alerts': f'http://localhost:8000/alerts?limit=5',
        'Agent Status': f'http://localhost:8000/agents?limit=5',
        'System Stats': f'http://localhost:8000/stats',
    }
    
    for endpoint_name, url in endpoints.items():
        checks_total += 1
        ok, msg = check_http_endpoint(url, headers)
        if check(ok, endpoint_name):
            checks_passed += 1
            info(f"  {msg}")
        else:
            warn(f"  {msg}")
    
    # === SECTION 7: Agent Configuration ===
    section("7. Agent Configuration")
    
    checks_total += 1
    gateway_url = env.get('AEGIS_GATEWAY_URL', 'http://aegis-link:8080/api/v1/events')
    if check(gateway_url, "Gateway URL"):
        checks_passed += 1
        info(f"  {gateway_url}")
    
    checks_total += 1
    scan_interval = env.get('AEGIS_SCAN_INTERVAL_MS', '1000')
    if check(scan_interval, "Scan Interval (ms)"):
        checks_passed += 1
        info(f"  {scan_interval}ms")
    
    # === FINAL REPORT ===
    section("Final Report")
    
    percentage = (checks_passed / checks_total * 100) if checks_total > 0 else 0
    color = Colors.OKGREEN if percentage >= 80 else (Colors.WARN if percentage >= 60 else Colors.FAIL)
    
    print(f"Checks Passed: {checks_passed}/{checks_total}")
    print(f"Success Rate: {color}{percentage:.1f}%{Colors.RESET}\n")
    
    if percentage >= 90:
        print(f"{Colors.OKGREEN}✓ All systems operational!{Colors.RESET}")
    elif percentage >= 70:
        print(f"{Colors.WARN}⚠ Some issues detected. Review above.{Colors.RESET}")
    else:
        print(f"{Colors.FAIL}✗ Critical issues detected. See troubleshooting.{Colors.RESET}")
    
    print("\nTroubleshooting:")
    print("  - Check logs: docker-compose logs -f")
    print("  - Verify .env: cat .env | grep AEGIS_")
    print("  - Test connectivity: curl -H 'X-Api-Key: <KEY>' http://localhost:8000/stats")
    print("  - View agents: docker exec aegis-postgres psql -U aegis_user -d aegis -c 'SELECT * FROM agents;'")

if __name__ == '__main__':
    main()
