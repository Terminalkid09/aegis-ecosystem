import pytest

from honeypot.runner import _health_handler


class _Reader:
    def __init__(self, data: bytes = b"GET /health HTTP/1.1\r\n\r\n"):
        self.data = data

    async def read(self, _size: int) -> bytes:
        return self.data


class _Writer:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self.data += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


@pytest.mark.asyncio
async def test_health_handler_returns_200_and_closes():
    writer = _Writer()

    await _health_handler(_Reader(), writer)

    assert b"HTTP/1.1 200 OK" in writer.data
    assert writer.closed is True


@pytest.mark.asyncio
async def test_health_handler_ignores_empty_probe():
    writer = _Writer()

    await _health_handler(_Reader(b""), writer)

    assert b"200 OK" in writer.data
    assert writer.closed is True
