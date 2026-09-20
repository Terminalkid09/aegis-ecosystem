import types
from app.services.detection_context import is_trusted_signed, user_role, build_evidence

def _ev(**kw):
    return types.SimpleNamespace(
        process_name=kw.get("process_name", "test.exe"),
        process_path=kw.get("process_path", "C:\\Windows\\System32\\test.exe"),
        parent_process_name=kw.get("parent_process_name", "explorer.exe"),
        pid=kw.get("pid", 123),
        parent_pid=kw.get("parent_pid", 1),
        user=kw.get("user", "jdoe"),
        command_line=kw.get("command_line"),
        signature=kw.get("signature"),
        publisher=kw.get("publisher"),
        file_hash=kw.get("file_hash"),
        network_connections=kw.get("network_connections"),
        provenance=kw.get("provenance"),
        quality=kw.get("quality"),
        proto=kw.get("proto"),
        direction=kw.get("direction"),
    )

def test_trusted_signed_true():
    ev = _ev(signature="authenticode-trusted", publisher="Microsoft Windows")
    assert is_trusted_signed(ev) is True

def test_trusted_signed_false_unsigned():
    ev = _ev(signature="unsigned:0x800b0100", publisher="Microsoft Windows")
    assert is_trusted_signed(ev) is False

def test_trusted_signed_false_untrusted_publisher():
    ev = _ev(signature="authenticode-trusted", publisher="Evil Corp")
    assert is_trusted_signed(ev) is False

def test_user_role():
    assert user_role(_ev(user="NT AUTHORITY\\SYSTEM")) == "privileged"
    assert user_role(_ev(user="root")) == "privileged"
    assert user_role(_ev(user="jdoe")) == "standard"
    assert user_role(_ev(user="")) == "standard"

def test_build_evidence_shape():
    ev = _ev(process_name="powershell.exe", parent_process_name="winword.exe", publisher="Microsoft Corporation", signature="authenticode-trusted", file_hash="abc")
    rule = types.SimpleNamespace(rule_id="AEGIS-S002", version="1.0", severity="CRITICAL", confidence="high", description="parent child", mitre_technique_id="T1204")
    ctx = {"prevalence": {"seen_count": 2}, "first_seen": "2024-01-01", "reputation": "clean"}
    evd = build_evidence(ev, [rule], ctx)
    assert evd["process"]["name"] == "powershell.exe"
    assert evd["identity"]["trusted"] is True
    assert evd["identity"]["hash"] == "abc"
    assert evd["rules"][0]["id"] == "AEGIS-S002"
    assert evd["rules"][0]["confidence"] == "high"
    assert evd["prevalence"]["seen_count"] == 2
    assert evd["process"]["role"] == "standard"

def test_build_evidence_no_trust_for_unsigned():
    ev = _ev(signature="unsigned", publisher="")
    rule = types.SimpleNamespace(rule_id="AEGIS-S009", version="1.0", severity="MEDIUM", confidence="low", description="x", mitre_technique_id=None)
    evd = build_evidence(ev, [rule], {})
    assert evd["identity"]["trusted"] is False

def test_suppress_trusted_low_severity():
    # Lo script interpreter trusted non deve alzare confidence alta
    ev = _ev(process_name="powershell.exe", signature="authenticode-trusted", publisher="Microsoft Corporation")
    assert is_trusted_signed(ev) is True


def test_untrusted_string_is_not_trusted():
    # Audit: "untrusted"/"distrusted" contengono "trusted" ma non sono trust.
    assert is_trusted_signed(_ev(signature="untrusted", publisher="Microsoft Corporation")) is False
    assert is_trusted_signed(_ev(signature="distrusted", publisher="Microsoft Corporation")) is False
    assert is_trusted_signed(_ev(signature="not-trusted", publisher="Microsoft Corporation")) is False


def test_publisher_spoof_is_not_trusted():
    # Audit: match esatto publisher ("evil microsoft corporation" no).
    assert is_trusted_signed(_ev(signature="authenticode-trusted",
                                 publisher="evil microsoft corporation trojan")) is False
    assert is_trusted_signed(_ev(signature="authenticode-trusted",
                                 publisher=" Microsoft Corporation ")) is True


def test_file_hash_is_not_trust():
    # Audit: l'hash identifica, non certifica (niente fallback).
    assert is_trusted_signed(_ev(signature=None, file_hash="abc123",
                                 publisher="Microsoft Corporation")) is False
