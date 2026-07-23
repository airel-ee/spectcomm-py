import socket
import threading

import cbor2
import pytest

from airel.spectcomm.airdaq import AirdaqError, AirdaqRemote, AirdaqStreamConnection


def send(sock, msg):
    data = cbor2.dumps(msg)
    sock.sendall(len(data).to_bytes(2, "big") + data)


def send_fragmented(sock, msg):
    data = cbor2.dumps(msg)
    sock.sendall((0x8000 | 3).to_bytes(2, "big") + data[:3])
    sock.sendall((0x8000).to_bytes(2, "big"))  # keepalive between fragments
    sock.sendall(len(data[3:]).to_bytes(2, "big") + data[3:])


def recv(sock):
    header = sock.recv(2)
    if not header:
        return None
    size = int.from_bytes(header, "big") & 0x7FFF
    buf = bytearray()
    while len(buf) < size:
        buf += sock.recv(size - len(buf))
    return cbor2.loads(bytes(buf))


RECORD_META = {
    "t": "record_meta",
    "channel": "raw",
    "fields": [
        {"id": 0, "key": "em_voltage", "dtype": "f64", "unit": "V"},
        {"id": 1, "key": "em_current", "dtype": "vec<f64>", "size": 3, "unit": "A"},
        {"id": 2, "key": "broken_vec", "dtype": "vec<f64>"},  # no size: unusable
        {"id": 50, "key": "opmode", "dtype": "string"},
    ],
}


def fake_server(sock):
    c_hello = recv(sock)
    assert c_hello["t"] == "hello"
    assert c_hello["version"] == 2
    send(
        sock,
        {
            "t": "hello",
            "protocol": "airdaq",
            "version": 2,
            "nonce": c_hello["nonce"],
            "capabilities": [],
            "device_id": "nais-7-32",
            "make": "Airel",
            "model": "NAIS-7",
            "hw_version": "rev-C",
            "fw_version": "1.4.2",
        },
    )
    send(
        sock,
        {
            "t": "settings",
            "values": {"flow_target": 25, "flow_control": None},
            "meta": {"flow_target": {"dtype": "f64", "default": 20.0}},
        },
    )
    send_fragmented(
        sock, {"t": "state", "values": {"uptime_ns": 86400, "temperature": 32.5}}
    )
    send(sock, {"t": "future_push", "mystery": 1})  # must be tolerated
    send(sock, {"t": "control", "has_control": False})
    send(sock, {"t": "channels", "channels": {"raw": {"kind": "record"}}})
    send(sock, {"t": "ready"})

    m = recv(sock)
    assert m == {"t": "subscribe", "id": m["id"], "channels": ["raw"]}
    send(sock, {"t": "ok", "id": m["id"], "result": None})
    send(sock, RECORD_META)
    send(
        sock,
        {
            "t": "record",
            "channel": "raw",
            "ts": 1000,
            "snapshot": True,
            "values": {0: 1, 1: [1, 2, 3], 2: [9, 9], 50: "idle", 60: "extra"},
        },
    )
    send(sock, {"t": "beacon", "ts": 1500, "unix": 1_000_000_000})
    send(sock, {"t": "record", "channel": "raw", "ts": 2000, "values": {0: 2.5}})

    m = recv(sock)
    assert m == {"t": "set", "id": m["id"], "key": "flow_target", "value": 30.0}
    send(sock, {"t": "ok", "id": m["id"], "result": None})
    send(sock, {"t": "settings", "values": {"flow_target": 30.0}})

    m = recv(sock)
    assert m["t"] == "set"
    send(
        sock,
        {
            "t": "err",
            "id": m["id"],
            "error": {"code": "invalid_params", "message": "exceeds max 100"},
        },
    )

    m = recv(sock)
    assert m["t"] == "ping"
    send(sock, {"t": "ok", "id": m["id"], "result": 86408})

    m = recv(sock)
    assert m == {"t": "request_control", "id": m["id"], "priority": 5}
    send(sock, {"t": "ok", "id": m["id"], "result": None})
    send(sock, {"t": "control", "has_control": True})

    sock.close()


@pytest.fixture
def dev():
    client_sock, server_sock = socket.socketpair()
    t = threading.Thread(target=fake_server, args=(server_sock,), daemon=True)
    t.start()
    with AirdaqRemote(AirdaqStreamConnection(client_sock), client_name="t@h") as dev:
        yield dev
    t.join(timeout=5)


def test_session(dev):
    assert dev.ready
    assert dev.device_id == "nais-7-32"
    assert dev.model == "NAIS-7"
    # int 25 coerced to float via the declared f64 dtype; untyped key untouched
    assert dev.settings == {"flow_target": 25.0, "flow_control": None}
    assert isinstance(dev.settings["flow_target"], float)
    assert dev.state == {"uptime_ns": 86400, "temperature": 32.5}
    assert dev.control == {"t": "control", "has_control": False}
    assert dev.channels == {"raw": {"kind": "record"}}

    dev.subscribe(["raw"])
    assert dev.subscriptions == {"raw"}

    recs = dev.records()
    snapshot = next(recs)
    assert snapshot["snapshot"] is True
    # ids mapped to keys, ints coerced to floats, unusable/unknown fields
    # kept raw under their wire ids
    assert snapshot["values"] == {
        "em_voltage": 1.0,
        "em_current": [1.0, 2.0, 3.0],
        "opmode": "idle",
        2: [9, 9],
        60: "extra",
    }
    live = next(recs)
    assert live["ts"] == 2000
    assert live["values"] == {"em_voltage": 2.5}

    assert dev.unix_ns(2000) == 1_000_000_000 + 500

    dev.set("flow_target", 30.0)
    dev.next_message(timeout=5)  # the settings delta push
    assert dev.settings["flow_target"] == 30.0

    with pytest.raises(AirdaqError) as e:
        dev.set("flow_target", 999.0)
    assert e.value.code == "invalid_params"

    assert dev.ping() == 86408
    assert dev.request_control(priority=5) is True
