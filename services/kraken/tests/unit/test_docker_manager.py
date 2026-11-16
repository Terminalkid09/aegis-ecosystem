import io
import tarfile

from app.services import docker_manager as dm
from app.services.sandbox_policy import SANDBOX_RUN_KWARGS


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def test_sandbox_policy_has_no_network_and_read_only_rootfs():
    assert SANDBOX_RUN_KWARGS["network_mode"] == "none"
    assert SANDBOX_RUN_KWARGS["read_only"] is True
    assert SANDBOX_RUN_KWARGS["cap_drop"] == ["ALL"]
    assert SANDBOX_RUN_KWARGS["security_opt"] == ["no-new-privileges:true"]
    assert "/tmp" in SANDBOX_RUN_KWARGS["tmpfs"]
    assert "network" not in SANDBOX_RUN_KWARGS


def test_safe_extract_enforces_file_and_total_caps(tmp_path):
    payload = _tar_bytes(
        {
            "small.txt": b"12345",
            "large.txt": b"x" * 50,
            "second.txt": b"67890",
        }
    )
    with tarfile.open(fileobj=io.BytesIO(payload)) as tar:
        results = dm._safe_extract(
            tar, str(tmp_path), max_file_bytes=10, max_total_bytes=5
        )

    names = {item["filename"] for item in results}
    assert names == {"small.txt"}
    assert (tmp_path / results[0]["sha256"]).read_bytes() == b"12345"


def test_safe_extract_skips_path_traversal(tmp_path):
    payload = _tar_bytes({"../evil.txt": b"evil", "ok.txt": b"ok"})
    with tarfile.open(fileobj=io.BytesIO(payload)) as tar:
        results = dm._safe_extract(tar, str(tmp_path))

    assert [item["filename"] for item in results] == ["ok.txt"]
    assert not (tmp_path.parent / "evil.txt").exists()

