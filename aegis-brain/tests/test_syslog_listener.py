"""Listener syslog: meccanica della coda e accodamento dei messaggi.

Il listener è il pezzo che permette a un firewall o a un rsyslog di puntare
direttamente sulla piattaforma. Qui si verifica ciò che può rompersi in
produzione senza toccare il DB: che un syslog storm non accumuli memoria,
che i datagrammi siano decodificati e accodati, e che lo stato esposto
dall'health sia coerente.
"""
from app.services.syslog_server import MAX_QUEUE, SyslogListener, _UdpProtocol


def _listener(**kwargs) -> SyslogListener:
    # Porta 0 = nessuna porta reale: qui si testa solo l'accodamento.
    kwargs.setdefault("port", 0)
    kwargs.setdefault("with_tcp", False)
    return SyslogListener(host="127.0.0.1", **kwargs)


def test_offer_enqueues_and_counts_received():
    listener = _listener()
    listener.offer("<134>1 2026-09-15T12:00:01Z web-01 sshd - Failed password")
    assert listener.stats["received"] == 1
    assert listener.stats["dropped"] == 0
    assert listener.queue.qsize() == 1
    line, peer = listener.queue.get_nowait()
    assert line.startswith("<134>1")
    assert peer is None


def test_queue_full_drops_instead_of_growing():
    """Un produttore più veloce del consumatore non deve uccidere il processo."""
    listener = _listener()
    for i in range(MAX_QUEUE):
        listener.offer(f"msg-{i}")
    assert listener.queue.qsize() == MAX_QUEUE
    # Oltre la capacità: si scarta e si conta, la memoria resta limitata.
    listener.offer("msg-overflow")
    assert listener.queue.qsize() == MAX_QUEUE
    assert listener.stats["dropped"] == 1
    assert listener.stats["received"] == MAX_QUEUE + 1


def test_udp_datagram_is_decoded_and_trimmed():
    listener = _listener()
    protocol = _UdpProtocol(listener)
    protocol.datagram_received(
        b"<13>Sep 15 12:00:01 host app[1]: hello\r\n", ("203.0.113.7", 514))
    line, peer = listener.queue.get_nowait()
    assert line == "<13>Sep 15 12:00:01 host app[1]: hello"
    assert peer == ("203.0.113.7", 514)


def test_udp_empty_datagram_is_ignored():
    listener = _listener()
    protocol = _UdpProtocol(listener)
    protocol.datagram_received(b"\r\n", ("203.0.113.7", 514))
    assert listener.queue.qsize() == 0
    assert listener.stats["received"] == 0


def test_health_reports_state_before_start():
    listener = _listener(port=5514)
    health = listener.health()
    assert health["running"] is False
    assert health["tcp"] is False
    assert health["bind"] == "127.0.0.1:5514"
    assert health["queue_capacity"] == MAX_QUEUE
    for key in ("received", "dropped", "ingested", "stored", "alerts", "errors"):
        assert health[key] == 0


async def test_start_and_stop_bind_udp_and_tcp():
    """Il ciclo di vita reale: si lega una porta effimera, si chiude pulito."""
    listener = SyslogListener(host="127.0.0.1", port=0, with_tcp=True)
    await listener.start()
    assert listener._running is True
    # Con porta 0 il sistema operativo assegna la porta: il listener deve
    # comunque essere in ascolto su UDP e TCP.
    assert listener._transports, "UDP non è stato legato"
    assert listener._server is not None, "TCP non è stato legato"
    await listener.stop()
    assert listener._running is False
    assert not listener._transports
    assert listener._server is None


async def test_double_start_is_idempotent():
    listener = SyslogListener(host="127.0.0.1", port=0, with_tcp=False)
    await listener.start()
    first = list(listener._transports)
    await listener.start()          # seconda chiamata: no-op
    assert listener._transports == first
    await listener.stop()


async def test_stop_is_safe_without_start():
    listener = _listener()
    await listener.stop()           # non deve sollevare
    assert listener._running is False
