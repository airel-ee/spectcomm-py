# spectcomm-py

Python clients for Airel instrument remote-control protocols:

- `airel.spectcomm.airdaq` — airdaq v2 (CBOR over TCP / Unix socket / USB)
- `airel.spectcomm.SpectCoreRemote` — SRCP/4.0–5.0 (socket or serial)
- `airel.spectcomm.SpectopsRemote` — SORCP/4.0

## airdaq

```python
from airel.spectcomm import airdaq

dev = airdaq.connect()        # LAN discovery; or connect("10.0.0.5", 1234),
                              # connect(socket_path=...), airdaq.connect_usb()
print(dev.device_id, dev.model, dev.channels)

dev.subscribe(["raw"])
for rec in dev.records():
    print(rec["ts"], rec["values"])
```

A background reader thread drains the connection: it keeps
`dev.settings` / `dev.state` current, sends the idle-timeout keepalive,
and feeds records, beacons, events, and logs — each stamped with the
receive wall clock as `rx_unix_ns` — to `dev.next_message()` /
`dev.records()`. Writes go through
`dev.set(key, value)` / `dev.unset(key)`; device actions through
`dev.command(key, params)`. On servers that arbitrate control, call
`dev.request_control(priority)` first.
