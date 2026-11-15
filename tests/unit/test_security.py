import pytest
from app.core.security import (
    hash_password, verify_password, create_access_token, create_refresh_token,
    decode_access_token, decode_access_payload, verify_internal_api_key,
)
from app.core.config import settings
from app.schemas.schemas import SensorEventIn, LoginRequest
from fastapi import HTTPException
from pydantic import ValidationError
import pytest
import time


class TestPasswordHashing:
    def test_hash_and_verify(self):
        password = "MySecureP@ssw0rd123!"
        hashed = hash_password(password)
        assert verify_password(password, hashed)
        assert not verify_password("wrong", hashed)

    def test_different_hashes_for_same_password(self):
        password = "samepassword"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        assert hash1 != hash2
        assert verify_password(password, hash1)
        assert verify_password(password, hash2)


class TestJWT:
    def test_create_and_decode_token(self):
        token = create_access_token(subject="testuser")
        payload = decode_access_token(token)
        assert payload == "testuser"

    def test_token_expiry(self):
        from datetime import timedelta
        token = create_access_token(subject="testuser", expires_delta=timedelta(seconds=1))
        time.sleep(2)
        payload = decode_access_token(token)
        assert payload is None

    def test_invalid_token(self):
        payload = decode_access_token("invalid.token.here")
        assert payload is None

    def test_tampered_token(self):
        token = create_access_token(subject="testuser")
        parts = token.split(".")
        tampered = parts[0] + "." + parts[1] + ".tampered"
        payload = decode_access_token(tampered)
        assert payload is None

    def test_refresh_token_not_accepted_as_access(self):
        token = create_refresh_token(subject="testuser")
        payload = decode_access_token(token)
        assert payload is None

    def test_access_payload_has_jti(self):
        payload = decode_access_payload(create_access_token(subject="testuser"))
        assert payload is not None and payload["jti"]


class TestInternalApiKey:
    def test_accepts_matching_key(self, monkeypatch):
        key = "a" * 64
        monkeypatch.setattr(settings, "INTERNAL_API_KEY", key)
        assert verify_internal_api_key(key) == key

    def test_rejects_wrong_key(self, monkeypatch):
        monkeypatch.setattr(settings, "INTERNAL_API_KEY", "a" * 64)
        with pytest.raises(HTTPException):
            verify_internal_api_key("b" * 64)


class TestInputValidation:
    def test_valid_sensor_event(self):
        event = SensorEventIn(
            sensor_type="ssh",
            attacker_ip="192.168.1.1",
            attacker_port=22,
            sensor_port=2222,
            session_id="test-session-001",
            username="admin",
            password="password",
            commands=["whoami", "ls -la"]
        )
        assert event.sensor_type == "ssh"
        assert event.attacker_ip == "192.168.1.1"

    def test_invalid_sensor_type(self):
        with pytest.raises(ValidationError):
            SensorEventIn(
                sensor_type="invalid",
                attacker_ip="192.168.1.1",
                attacker_port=22,
                sensor_port=2222,
                session_id="test-session-001"
            )

    def test_invalid_ip_format(self):
        with pytest.raises(ValidationError):
            SensorEventIn(
                sensor_type="ssh",
                attacker_ip="not.an.ip",
                attacker_port=22,
                sensor_port=2222,
                session_id="test-session-001"
            )

    def test_command_truncation(self):
        long_commands = ["a" * 600 for _ in range(250)]
        event = SensorEventIn(
            sensor_type="ssh",
            attacker_ip="192.168.1.1",
            attacker_port=22,
            sensor_port=2222,
            session_id="test-session-001",
            commands=long_commands
        )
        assert len(event.commands) == 200
        assert all(len(c) <= 512 for c in event.commands)

    def test_login_request_validation(self):
        login = LoginRequest(username="user", password="pass")
        assert login.username == "user"

    def test_login_request_username_too_long(self):
        with pytest.raises(ValidationError):
            LoginRequest(username="a" * 65, password="pass")


class TestSensorEventValidation:
    def test_all_sensor_types(self):
        for sensor in ["ssh", "http", "ftp", "telnet", "smtp", "rdp"]:
            event = SensorEventIn(
                sensor_type=sensor,
                attacker_ip="10.0.0.1",
                attacker_port=1234,
                sensor_port=2222,
                session_id="test-session"
            )
            assert event.sensor_type == sensor

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            SensorEventIn(sensor_type="ssh")

    def test_port_bounds(self):
        with pytest.raises(ValidationError):
            SensorEventIn(
                sensor_type="ssh", attacker_ip="10.0.0.1",
                attacker_port=0, sensor_port=2222, session_id="test"
            )
        with pytest.raises(ValidationError):
            SensorEventIn(
                sensor_type="ssh", attacker_ip="10.0.0.1",
                attacker_port=65536, sensor_port=2222, session_id="test"
            )