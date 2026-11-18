"""
Security tests — verifica che tutti gli input malevoli vengano rigettati
prima di toccare il database o la logica di business.
"""
import pytest
from pydantic import ValidationError
from app.schemas.schemas import SensorEventIn, UserCreate, LoginRequest


# ── SensorEventIn — validazione IP ───────────────────────────────────────────

class TestIPValidation:
    def test_rejects_script_tag_as_ip(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="ssh", attacker_ip="<script>alert(1)</script>",
                          attacker_port=22, sensor_port=2222, session_id="test-xss-001")

    def test_rejects_sql_injection_as_ip(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="ssh", attacker_ip="1.2.3.4' OR '1'='1",
                          attacker_port=22, sensor_port=2222, session_id="test-sqli-001")

    def test_rejects_null_byte_in_ip(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="ssh", attacker_ip="1.2.3.4\x00",
                          attacker_port=22, sensor_port=2222, session_id="test-null-001")

    def test_rejects_empty_ip(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="ssh", attacker_ip="",
                          attacker_port=22, sensor_port=2222, session_id="test-empty-001")

    def test_rejects_ip_too_long(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="ssh", attacker_ip="A" * 100,
                          attacker_port=22, sensor_port=2222, session_id="test-long-001")

    def test_accepts_valid_ipv4(self):
        p = SensorEventIn(sensor_type="ssh", attacker_ip="192.168.1.100",
                          attacker_port=22, sensor_port=2222, session_id="test-valid-001")
        assert p.attacker_ip == "192.168.1.100"

    def test_accepts_valid_ipv6(self):
        p = SensorEventIn(sensor_type="ssh", attacker_ip="2001:db8::1",
                          attacker_port=22, sensor_port=2222, session_id="test-v6-001")
        assert p.attacker_ip == "2001:db8::1"


# ── SensorEventIn — validazione sensor_type ──────────────────────────────────

class TestSensorTypeValidation:
    def test_rejects_unknown_sensor(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="unknown_sensor", attacker_ip="1.2.3.4",
                          attacker_port=22, sensor_port=2222, session_id="test-sensor-001")

    def test_rejects_sql_injection_as_sensor(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="ssh; DROP TABLE attack_events;--",
                          attacker_ip="1.2.3.4", attacker_port=22,
                          sensor_port=2222, session_id="test-sqli-sensor-001")

    def test_rejects_empty_sensor(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="", attacker_ip="1.2.3.4",
                          attacker_port=22, sensor_port=2222, session_id="test-empty-sensor-001")

    def test_normalises_uppercase_sensor(self):
        p = SensorEventIn(sensor_type="SSH", attacker_ip="1.2.3.4",
                          attacker_port=22, sensor_port=2222, session_id="test-case-001")
        assert p.sensor_type == "ssh"

    def test_accepts_all_valid_sensors(self):
        for sensor in ["ssh", "http", "ftp", "telnet", "smtp", "rdp", "smb"]:
            p = SensorEventIn(sensor_type=sensor, attacker_ip="1.2.3.4",
                              attacker_port=22, sensor_port=2222,
                              session_id=f"test-valid-{sensor}")
            assert p.sensor_type == sensor

    def test_rejects_unknown_context(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="ssh", attacker_ip="1.2.3.4",
                          attacker_port=22, sensor_port=2222,
                          session_id="test-context-001", context="production")


# ── SensorEventIn — porta ─────────────────────────────────────────────────────

class TestPortValidation:
    def test_rejects_port_zero(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="ssh", attacker_ip="1.2.3.4",
                          attacker_port=0, sensor_port=2222, session_id="test-port-001")

    def test_rejects_port_above_65535(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="ssh", attacker_ip="1.2.3.4",
                          attacker_port=99999, sensor_port=2222, session_id="test-port-002")

    def test_accepts_valid_ports(self):
        p = SensorEventIn(sensor_type="ssh", attacker_ip="1.2.3.4",
                          attacker_port=1, sensor_port=65535, session_id="test-port-003")
        assert p.attacker_port == 1 and p.sensor_port == 65535


# ── SensorEventIn — comandi ───────────────────────────────────────────────────

class TestCommandValidation:
    def test_truncates_oversized_command(self):
        p = SensorEventIn(sensor_type="http", attacker_ip="1.2.3.4",
                          attacker_port=80, sensor_port=8080, session_id="test-cmd-001",
                          commands=["X" * 2000])
        assert len(p.commands[0]) == 512

    def test_caps_command_list_at_200(self):
        p = SensorEventIn(sensor_type="http", attacker_ip="1.2.3.4",
                          attacker_port=80, sensor_port=8080, session_id="test-cmd-002",
                          commands=[f"cmd{i}" for i in range(250)])
        assert len(p.commands) == 200

    def test_none_commands_become_empty_list(self):
        p = SensorEventIn(sensor_type="ssh", attacker_ip="1.2.3.4",
                          attacker_port=22, sensor_port=2222, session_id="test-cmd-003",
                          commands=None)
        assert p.commands == []

    def test_sql_injection_in_command_is_stored_as_text(self):
        """Injection in commands should be stored safely, not executed."""
        cmd = "GET /'; DROP TABLE attack_events; --"
        p = SensorEventIn(sensor_type="http", attacker_ip="1.2.3.4",
                          attacker_port=80, sensor_port=8080, session_id="test-cmd-004",
                          commands=[cmd])
        assert p.commands[0] == cmd  # stored as plain text, not interpreted


# ── SensorEventIn — credenziali ───────────────────────────────────────────────

class TestCredentialValidation:
    def test_truncates_oversized_username(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="ssh", attacker_ip="1.2.3.4",
                          attacker_port=22, sensor_port=2222, session_id="test-cred-001",
                          username="U" * 200)

    def test_truncates_oversized_password(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="ssh", attacker_ip="1.2.3.4",
                          attacker_port=22, sensor_port=2222, session_id="test-cred-002",
                          password="P" * 300)

    def test_none_credentials_are_allowed(self):
        p = SensorEventIn(sensor_type="ssh", attacker_ip="1.2.3.4",
                          attacker_port=22, sensor_port=2222, session_id="test-cred-003")
        assert p.username is None and p.password is None


# ── UserCreate — validazione password ────────────────────────────────────────

class TestUserCreateValidation:
    def test_rejects_short_password(self):
        with pytest.raises(ValidationError):
            UserCreate(username="validuser", password="short")

    def test_rejects_empty_username(self):
        with pytest.raises(ValidationError):
            UserCreate(username="", password="validpassword123")

    def test_rejects_username_with_special_chars(self):
        with pytest.raises(ValidationError):
            UserCreate(username="user; DROP TABLE users;--", password="validpassword123")

    def test_rejects_username_too_short(self):
        with pytest.raises(ValidationError):
            UserCreate(username="ab", password="validpassword123")

    def test_accepts_valid_username_formats(self):
        for name in ["validuser", "valid_user", "valid-user", "ValidUser123"]:
            u = UserCreate(username=name, password="validpassword123")
            assert u.username == name


# ── LoginRequest — validazione ───────────────────────────────────────────────

class TestLoginRequestValidation:
    def test_rejects_empty_username(self):
        with pytest.raises(ValidationError):
            LoginRequest(username="", password="somepassword")

    def test_rejects_empty_password(self):
        with pytest.raises(ValidationError):
            LoginRequest(username="admin", password="")

    def test_rejects_oversized_username(self):
        with pytest.raises(ValidationError):
            LoginRequest(username="A" * 200, password="somepassword")

    def test_rejects_oversized_password(self):
        with pytest.raises(ValidationError):
            LoginRequest(username="admin", password="P" * 200)

    def test_accepts_valid_login(self):
        req = LoginRequest(username="admin", password="securepassword")
        assert req.username == "admin"
