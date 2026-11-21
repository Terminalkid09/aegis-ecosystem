import struct

from honeypot.sensors.smb_sensor import parse_ntlm_type3, _ntlm_type2
from honeypot.sensors.rdp_sensor import _X224_CONFIRM


def _type3(username="alice", domain="LAB", response=b"R" * 32):
    user = username.encode("utf-16-le")
    dom = domain.encode("utf-16-le")
    # NTLMSSP offsets are relative to the start of the message, whose header
    # is 64 bytes; the test has no transport prefix before the signature.
    header_len = 64
    nt_off = header_len + len(dom) + len(user)
    header = bytearray(header_len)
    header[0:8] = b"NTLMSSP\x00"
    struct.pack_into("<I", header, 8, 3)
    # NT response fields at 20, domain at 28, user at 36.
    struct.pack_into("<HHI", header, 20, len(response), len(response), nt_off)
    struct.pack_into("<HHI", header, 28, len(dom), len(dom), header_len)
    struct.pack_into("<HHI", header, 36, len(user), len(user), header_len + len(dom))
    return bytes(header) + dom + user + response


def test_parse_netntlmv2_captures_user_domain_and_response():
    parsed = parse_ntlm_type3(_type3(), b"12345678")
    assert parsed is not None
    assert parsed["username"] == "alice"
    assert parsed["domain"] == "LAB"
    assert parsed["ntlm_hash"].startswith("alice::LAB:3132333435363738:")


def test_type2_has_valid_ntlmssp_signature_and_challenge():
    challenge = b"12345678"
    packet = _ntlm_type2(challenge)
    assert packet.startswith(b"NTLMSSP\x00\x02\x00\x00\x00")
    assert challenge in packet


def test_rdp_banner_is_a_connection_confirm():
    # X.224 Connection Confirm (0xd0) rather than a bare TCP accept.
    assert _X224_CONFIRM[5] == 0xD0
    assert len(_X224_CONFIRM) >= 11
