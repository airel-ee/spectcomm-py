"""Client for the airdaq v2 remote-control protocol.

CBOR request/response + push protocol spoken by Airel airdaq devices,
over TCP / Unix sockets (length-prefixed framing) or USB vendor bulk
endpoints (COBS framing).  Outbound message maps are built with "t" as
the first key -- a protocol encoder obligation.
"""

import getpass
import errno
import ipaddress
import itertools
import queue
import random
import selectors
import socket
import threading
import time

import cbor2
from cobs import cobs

PROTOCOL_VERSION = 2
DISCOVERY_PORT = 55404
MAX_MESSAGE = 1 << 20  # our inbound bound, advertised as max_message in c-hello

# Shared V-USB vendor space: VID:PID alone is not identity; the interface
# signature (class 0xFF, subclass 'A') and manufacturer string complete it.
USB_VID = 0x16C0
USB_PID = 0x05DC
USB_SUBCLASS = 0x41


class AirdaqError(Exception):
    """A failed request or session.

    For an `err` response, `code` is its code and `error` the whole `error`
    map, structured fields included (spec section 10); both are None otherwise.
    """

    def __init__(self, message, code=None, error=None):
        super().__init__(message)
        self.code = code
        self.error = error


class AirdaqStreamConnection:
    """Framing over a connected TCP or Unix-domain socket.

    2-byte big-endian header per fragment: bit 15 = continuation, low 15
    bits = fragment length.
    """

    def __init__(self, sock):
        self.socket = sock
        self.peer_max_message = 8192
        # One socket timeout bounds both directions; each waits on its own
        # deadline instead.
        sock.setblocking(False)
        self._readable = selectors.DefaultSelector()
        self._readable.register(sock, selectors.EVENT_READ)
        self._writable = selectors.DefaultSelector()
        self._writable.register(sock, selectors.EVENT_WRITE)
        self._closing = threading.Lock()

    def handshake(self, hello):
        self.write(self.encode(hello), timeout=10)
        s_hello = self.receive_message(timeout=10)
        if s_hello is None:
            raise AirdaqError("no hello from server")
        return s_hello

    def encode(self, message):
        """The frame carrying `message`."""
        data = cbor2.dumps(message)
        if len(data) > self.peer_max_message:
            raise AirdaqError(
                "message of {} bytes exceeds peer limit of {}".format(
                    len(data), self.peer_max_message
                )
            )
        frame = bytearray()
        for pos in range(0, len(data), 0x7FFF):
            frag = data[pos : pos + 0x7FFF]
            more = 0x8000 if pos + len(frag) < len(data) else 0
            frame += (len(frag) | more).to_bytes(2, "big") + frag
        return bytes(frame)

    def write(self, frame, timeout):
        deadline = time.monotonic() + timeout
        view = memoryview(frame)
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._writable.select(remaining):
                raise TimeoutError("send timed out after {:g} s".format(timeout))
            try:
                view = view[self.socket.send(view) :]
            except BlockingIOError:
                continue

    def receive_message(self, timeout=60):
        payload = bytearray()
        while True:
            header = self._recv_exact(2, timeout, allow_none=not payload)
            if header is None:
                return None
            h = int.from_bytes(header, "big")
            size = h & 0x7FFF
            if size == 0:
                if not h & 0x8000:
                    raise AirdaqError("zero-length terminating fragment")
                continue  # keepalive
            if len(payload) + size > MAX_MESSAGE:
                raise AirdaqError("incoming message exceeds size limit")
            payload += self._recv_exact(size, timeout)
            if not h & 0x8000:
                try:
                    return cbor2.loads(bytes(payload))
                except cbor2.CBORDecodeError as e:
                    raise AirdaqError("invalid CBOR from server: {}".format(e))

    def _recv_exact(self, n, timeout, allow_none=False):
        buf = bytearray()
        while len(buf) < n:
            if not self._readable.select(timeout):
                if allow_none and not buf:
                    return None
                raise AirdaqError("timeout mid-message")
            try:
                chunk = self.socket.recv(n - len(buf))
            except BlockingIOError:
                continue
            if not chunk:
                raise AirdaqError("connection closed by server")
            buf += chunk
        return bytes(buf)

    def interrupt(self):
        """Wakes a send or receive waiting on the socket, which then fails."""
        with self._closing:
            if self.socket.fileno() == -1:
                return
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                # The peer already ended the connection: nothing waits on it.
                if e.errno != errno.ENOTCONN:
                    raise

    def close(self):
        with self._closing:
            self._readable.close()
            self._writable.close()
            self.socket.close()


class AirdaqUsbConnection:
    """COBS-framed CBOR over the device's vendor bulk endpoints.

    No length header, no CRC (USB guarantees integrity); one message per
    0x00-delimited frame.
    """

    def __init__(self, device):
        import usb.core
        import usb.util

        self.device = device
        self.peer_max_message = 8192
        self.buf = bytearray()

        # The first descriptor read opens the handle.
        try:
            try:
                cfg = device.get_active_configuration()
            except usb.core.USBError:
                device.set_configuration()
                cfg = device.get_active_configuration()

            self.intf = usb.util.find_descriptor(
                cfg,
                custom_match=lambda i: i.bInterfaceClass == 0xFF
                and i.bInterfaceSubClass == USB_SUBCLASS,
            )
            if self.intf is None:
                raise AirdaqError("device has no airdaq interface")
            if self.intf.bInterfaceProtocol != PROTOCOL_VERSION:
                raise AirdaqError(
                    "device speaks airdaq major {}, this client supports {}".format(
                        self.intf.bInterfaceProtocol, PROTOCOL_VERSION
                    )
                )

            usb.util.claim_interface(device, self.intf)
            self.ep_out = usb.util.find_descriptor(
                self.intf,
                custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress)
                == usb.util.ENDPOINT_OUT,
            )
            self.ep_in = usb.util.find_descriptor(
                self.intf,
                custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress)
                == usb.util.ENDPOINT_IN,
            )
            if self.ep_out is None or self.ep_in is None:
                raise AirdaqError("airdaq interface lacks bulk endpoints")
        except BaseException:
            usb.util.dispose_resources(device)
            raise

    def handshake(self, hello):
        # c-hello doubles as the connect / session-reset signal; the leading
        # 0x00 discards any stale partial frame in the device's parser.  The
        # nonce lets us reject s-hellos left over from a previous session.
        self.ep_out.write(b"\x00" + cobs.encode(cbor2.dumps(hello)) + b"\x00")
        deadline = time.monotonic() + 10
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AirdaqError("no hello from device")
            frame = self._receive_frame(remaining)
            if frame is None:
                continue
            try:
                msg = cbor2.loads(frame)
            except cbor2.CBORDecodeError:
                continue  # stale frame from a previous session
            if isinstance(msg, dict) and msg.get("t") == "hello":
                if msg.get("nonce") == hello["nonce"]:
                    return msg

    def encode(self, message):
        """The frame carrying `message`."""
        data = cbor2.dumps(message)
        if len(data) > self.peer_max_message:
            raise AirdaqError(
                "message of {} bytes exceeds peer limit of {}".format(
                    len(data), self.peer_max_message
                )
            )
        return cobs.encode(data) + b"\x00"

    def write(self, frame, timeout):
        if self.ep_out is None:
            raise AirdaqError("connection closed")
        self.ep_out.write(frame, int(timeout * 1000) + 1)

    def receive_message(self, timeout=60):
        if self.ep_in is None:
            raise AirdaqError("connection closed")
        frame = self._receive_frame(timeout)
        if frame is None:
            return None
        try:
            return cbor2.loads(frame)
        except cbor2.CBORDecodeError as e:
            raise AirdaqError("invalid CBOR from device: {}".format(e))

    def _receive_frame(self, timeout):
        import usb.core

        deadline = time.monotonic() + timeout
        while True:
            i = self.buf.find(0)
            if i >= 0:
                frame = bytes(self.buf[:i])
                del self.buf[: i + 1]
                if not frame:
                    continue  # empty frame: re-anchor no-op
                try:
                    return cobs.decode(frame)
                except cobs.DecodeError:
                    # A span clipped by a device-side buffer flush, not
                    # corruption; the delimiter keeps the stream aligned.
                    continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                chunk = self.ep_in.read(16384, int(remaining * 1000) + 1)
            except usb.core.USBTimeoutError:
                return None
            self.buf += bytes(chunk)

    def interrupt(self):
        """Nothing: closing the handle under a bulk transfer is undefined in
        libusb, and the transfer's timeout bounds it."""

    def close(self):
        import usb.util

        # release_interface raises on a disconnected device; dispose_resources
        # releases the claim regardless and closes the handle.
        usb.util.dispose_resources(self.device)
        # pyusb re-opens a disposed device, and re-claims its interface, on
        # its next transfer.
        self.ep_in = self.ep_out = None


def discover(timeout=0.5):
    """Broadcast an airdaq-discover probe; return the collected offers.

    Each offer dict gains an "address" key taken from the datagram source.
    """
    probe = cbor2.dumps({"t": "probe", "protocol": "airdaq-discover", "version": 1})
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    offers = []
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(probe, ("255.255.255.255", DISCOVERY_PORT))
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, src = sock.recvfrom(8192)
            except TimeoutError:
                break
            try:
                msg = cbor2.loads(data)
            except cbor2.CBORDecodeError:
                continue  # foreign traffic shares port 55404
            if (
                not isinstance(msg, dict)
                or msg.get("t") != "offer"
                or msg.get("protocol") != "airdaq-discover"
                or msg.get("version") != 1
            ):
                continue
            addr = ipaddress.ip_address(src[0])
            if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
                continue
            offer = dict(msg)
            offer["address"] = src[0]
            offers.append(offer)
    finally:
        sock.close()
    return offers


def connect(address=None, port=None, socket_path=None, device_id=None, client_name=None):
    """Connect over TCP or a Unix socket.

    Without an explicit (address, port), discovers devices on the LAN and
    connects to the single match (narrowed by device_id and/or address).
    """
    if socket_path is not None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(socket_path)
    else:
        if address is None or port is None:
            offers = discover()
            if device_id is not None:
                offers = [o for o in offers if o.get("device_id") == device_id]
            if address is not None:
                offers = [o for o in offers if o["address"] == address]
            usable = [
                o
                for o in offers
                if o.get("comm") == "airdaq"
                and o.get("comm_version") == PROTOCOL_VERSION
            ]
            if not usable:
                if offers:
                    raise AirdaqError(
                        "discovered devices, but none speak airdaq v{}: {}".format(
                            PROTOCOL_VERSION,
                            ", ".join(str(o.get("device_id")) for o in offers),
                        )
                    )
                raise AirdaqError("no airdaq devices discovered")
            if len(usable) > 1:
                raise AirdaqError(
                    "multiple devices discovered: {}; select with device_id".format(
                        ", ".join(str(o.get("device_id")) for o in usable)
                    )
                )
            address, port = usable[0]["address"], usable[0]["port"]
        sock = socket.create_connection((address, port), timeout=3)
    return AirdaqRemote(AirdaqStreamConnection(sock), client_name=client_name)


def connect_usb(device_id=None, client_name=None):
    """Connect to an airdaq device on the USB bus.

    With several devices attached, device_id (the descriptor serial number)
    selects one.
    """
    import usb.core

    def is_airdaq(dev):
        return any(
            intf.bInterfaceClass == 0xFF and intf.bInterfaceSubClass == USB_SUBCLASS
            for cfg in dev
            for intf in cfg
        )

    candidates = []
    for dev in usb.core.find(find_all=True, idVendor=USB_VID, idProduct=USB_PID):
        if not is_airdaq(dev):
            continue
        # pyusb raises ValueError ("no langid") for string descriptors it may
        # not read, as on a node udev has yet to grant access to.
        try:
            if dev.manufacturer != "Airel":
                continue
            serial = dev.serial_number
        except (usb.core.USBError, ValueError) as e:
            raise AirdaqError(
                "cannot read descriptors of USB device {:03d}:{:03d}: {} "
                "(check udev permissions)".format(dev.bus, dev.address, e)
            )
        if device_id is not None and serial != device_id:
            continue
        candidates.append((dev, serial))

    if not candidates:
        raise AirdaqError("no airdaq USB device found")
    if len(candidates) > 1:
        raise AirdaqError(
            "multiple airdaq USB devices found: {}; select with device_id".format(
                ", ".join(s for _, s in candidates)
            )
        )
    dev, serial = candidates[0]
    remote = AirdaqRemote(AirdaqUsbConnection(dev), client_name=client_name)
    if remote.device_id != serial:
        remote.close()
        raise AirdaqError(
            "descriptor serial {!r} does not match device_id {!r}".format(
                serial, remote.device_id
            )
        )
    return remote


def _coerce_float(value, dtype):
    # An encoder may compact an integral float (30.0 -> 30); the reverse
    # coercion is forbidden.  bool is an int subclass, so exclude it.
    if dtype in ("f32", "f64"):
        if isinstance(value, int) and not isinstance(value, bool):
            return float(value)
    elif dtype in ("vec<f32>", "vec<f64>", "list<f32>", "list<f64>"):
        if isinstance(value, list):
            return [
                float(v) if isinstance(v, int) and not isinstance(v, bool) else v
                for v in value
            ]
    return value


def _usable_field(f):
    # A vec<T> schema without size is unusable per spec: ignore the field.
    if "id" not in f or "key" not in f:
        return False
    if str(f.get("dtype", "")).startswith("vec<") and "size" not in f:
        return False
    return True


_SESSION_FAILED = object()


class AirdaqRemote:
    """An airdaq session over a stream or USB connection.

    A background reader thread drains the connection: it keeps the caches
    (state, settings, channels, commands, control) current, sends the
    idle_timeout keepalive on schedule, routes responses to waiting
    requests, and queues everything else -- stamped with the receive wall
    clock -- for next_message().  Requests may be issued from any thread.
    """

    def __init__(self, conn, client_name=None, wait_ready=True, queue_size=10000):
        self.conn = conn

        self.state = {}
        self.settings = {}
        self.state_meta = {}
        self.settings_meta = {}
        self.channels = {}
        self.commands = {}
        self.control = None
        self.record_meta = {}
        self.subscriptions = set()
        self.ready = False
        self._queue = queue.Queue(maxsize=queue_size)
        self._ids = itertools.count(1)
        self._field_ids = {}
        self._ping_ids = set()
        self._pending = {}
        self._error = None
        self._cond = threading.Condition()
        self._send_lock = threading.Lock()
        self._control_gen = 0

        if client_name is None:
            try:
                client_name = "{}@{}".format(getpass.getuser(), socket.gethostname())
            except OSError:
                client_name = "spectcomm-py"
        hello = {
            "t": "hello",
            "version": PROTOCOL_VERSION,
            "nonce": random.getrandbits(32),
            "max_message": MAX_MESSAGE,
            "capabilities": [],
            "client": {
                "name": client_name,
                "application": "spectcomm-py",
                "version": "0.1.0",
            },
        }
        try:
            self.hello = self.conn.handshake(hello)
            if self.hello.get("protocol") != "airdaq":
                raise AirdaqError(
                    "unexpected protocol {!r}".format(self.hello.get("protocol"))
                )
            if self.hello.get("version") != PROTOCOL_VERSION:
                raise AirdaqError(
                    "server speaks airdaq v{}, this client supports v{}".format(
                        self.hello.get("version"), PROTOCOL_VERSION
                    )
                )
            if "nonce" in self.hello and self.hello["nonce"] != hello["nonce"]:
                raise AirdaqError("server hello carries a foreign nonce")
        except BaseException:
            self.conn.close()
            raise
        self.conn.peer_max_message = self.hello.get("max_message", 8192)
        self.idle_timeout = self.hello.get("idle_timeout")
        self.device_id = self.hello.get("device_id")
        self.make = self.hello.get("make")
        self.model = self.hello.get("model")
        self.hw_version = self.hello.get("hw_version")
        # The serving implementation (spec section 1). sw_name is absent when it
        # is the model's stock software, so sw_version is scoped to the model.
        self.sw_name = self.hello.get("sw_name")
        self.sw_version = self.hello.get("sw_version")
        self._last_send = time.monotonic()

        self._reader = threading.Thread(
            target=self._reader_loop, name="airdaq-reader", daemon=True
        )
        self._reader.start()

        if wait_ready:
            try:
                self.wait_ready()
            except BaseException:
                self.close()
                raise

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        self._fail(AirdaqError("session closed"))
        self.conn.interrupt()
        # The reader closes the connection on its way out: on USB a handle
        # disposed under a transfer in flight is undefined in libusb.
        self._reader.join()

    def wait_ready(self, timeout=10):
        with self._cond:
            self._cond.wait_for(
                lambda: self.ready or self._error is not None, timeout
            )
            if self.ready:
                return
            if self._error is not None:
                raise self._error
            raise AirdaqError("timeout waiting for ready")

    def ping(self, timeout=60):
        """Return the server clock in ns on the ts axis."""
        return self._request({"t": "ping", "id": next(self._ids)}, timeout)

    def set(self, key, value, timeout=60):
        return self._request(
            {"t": "set", "id": next(self._ids), "key": key, "value": value}, timeout
        )

    def unset(self, key, timeout=60):
        """Revert a setting to its device default."""
        return self._request({"t": "unset", "id": next(self._ids), "key": key}, timeout)

    def subscribe(self, channels, timeout=60):
        """Replace the active subscription set; [] stops all channel traffic."""
        channels = list(channels)
        self._request(
            {"t": "subscribe", "id": next(self._ids), "channels": channels}, timeout
        )
        self.subscriptions = set(channels)

    def command(self, key, params=None, timeout=60):
        msg = {"t": "command", "id": next(self._ids), "key": key}
        if params is not None:
            msg["params"] = params
        return self._request(msg, timeout)

    def authenticate(self, password, timeout=60):
        return self._request(
            {"t": "authenticate", "id": next(self._ids), "password": password}, timeout
        )

    def request_control(self, priority=0, timeout=60):
        """Queue a control request; return has_control from the control push
        that follows every request_control."""
        with self._cond:
            gen = self._control_gen
        self._request(
            {"t": "request_control", "id": next(self._ids), "priority": priority},
            timeout,
        )
        with self._cond:
            self._cond.wait_for(
                lambda: self._control_gen > gen or self._error is not None, timeout
            )
            if self._control_gen <= gen:
                raise self._error or AirdaqError(
                    "no control push after request_control"
                )
        return self.control["has_control"]

    def drop_control(self, timeout=60):
        return self._request({"t": "drop_control", "id": next(self._ids)}, timeout)

    def next_message(self, timeout=60):
        """Return the next queued message, or None on timeout.

        Every queued message carries rx_unix_ns, the client wall clock at
        receipt.  The queue carries records (decoded), beacons, events,
        logs, record_meta, and cache pushes (after their side effects are
        applied); responses never appear.
        """
        try:
            msg = self._queue.get(timeout=timeout)
        except queue.Empty:
            if self._error is not None:
                raise self._error
            return None
        if msg is _SESSION_FAILED:
            try:
                self._queue.put_nowait(_SESSION_FAILED)
            except queue.Full:
                pass
            raise self._error
        return msg

    def records(self, channel=None, timeout=60):
        """Yield decoded record pushes, discarding other queued messages.

        Use a next_message() loop instead when events or logs matter.
        """
        while True:
            msg = self.next_message(timeout)
            if msg is None:
                raise AirdaqError("timeout waiting for records")
            if msg.get("t") == "record" and channel in (None, msg.get("channel")):
                yield msg

    def _send(self, message, timeout):
        # Refusing to encode a message leaves the session as it was.
        frame = self.conn.encode(message)
        with self._send_lock:
            if self._error is not None:
                raise self._error
            # A write cut short leaves a partial frame on the wire.
            try:
                self.conn.write(frame, timeout)
            except OSError as e:
                error = AirdaqError("send failed: {}".format(e))
                self._fail(error)
                raise error from e
            except BaseException as e:
                self._fail(
                    e
                    if isinstance(e, AirdaqError)
                    else AirdaqError("send interrupted: {!r}".format(e))
                )
                raise
            self._last_send = time.monotonic()

    def _request(self, msg, timeout=60):
        if self._error is not None:
            raise self._error
        event = threading.Event()
        slot = {}
        self._pending[msg["id"]] = (event, slot)
        deadline = time.monotonic() + timeout
        try:
            self._send(msg, timeout)
            if not event.wait(deadline - time.monotonic()):
                raise AirdaqError("timeout waiting for response")
        finally:
            self._pending.pop(msg["id"], None)
        m = slot["msg"]
        if isinstance(m, AirdaqError):
            raise m
        if m["t"] == "err":
            e = m.get("error", {})
            raise AirdaqError(
                "{}: {}".format(e.get("code"), e.get("message")),
                code=e.get("code"),
                error=e,
            )
        return m.get("result")

    def _reader_loop(self):
        try:
            while self._error is None:
                self._maybe_ping()
                tick = (
                    1.0
                    if self.idle_timeout is None
                    else min(1.0, self.idle_timeout / 4)
                )
                msg = self.conn.receive_message(tick)
                if msg is not None:
                    self._handle(msg)
        except AirdaqError as e:
            self._fail(e)
        except OSError as e:
            self._fail(AirdaqError("connection lost: {}".format(e)))
        except BaseException as e:
            self._fail(AirdaqError("reader failed: {!r}".format(e)))
            raise
        finally:
            self._close_conn()

    def _maybe_ping(self):
        # Client silence past idle_timeout invalidates the session (USB,
        # TCP half-open); any client message resets the timer.
        if (
            self.idle_timeout is not None
            and time.monotonic() - self._last_send > self.idle_timeout / 2
        ):
            msgid = next(self._ids)
            self._ping_ids.add(msgid)
            self._send({"t": "ping", "id": msgid}, self.idle_timeout / 2)

    def _handle(self, msg):
        t = msg.get("t")
        if t in ("ok", "err"):
            msgid = msg.get("id")
            if msgid in self._ping_ids:
                self._ping_ids.discard(msgid)
                return
            entry = self._pending.get(msgid)
            if entry is not None:
                event, slot = entry
                slot["msg"] = msg
                event.set()
                return
        msg["rx_unix_ns"] = time.time_ns()
        msg = self._process(msg)
        if t == "ready":
            with self._cond:
                self._cond.notify_all()
            return
        if t == "control":
            with self._cond:
                self._control_gen += 1
                self._cond.notify_all()
        if not self.ready:
            return  # initial sync lives in the caches, not the queue
        try:
            self._queue.put_nowait(msg)
        except queue.Full:
            raise AirdaqError("message queue full -- consumer too slow")

    def _fail(self, exc):
        """Ends the session with `exc`; the first failure stands."""
        with self._cond:
            if self._error is not None:
                return
            self._error = exc
            self._cond.notify_all()
        # A request whose response already arrived stays pending until its
        # caller wakes up and reads it.
        for event, slot in list(self._pending.values()):
            slot.setdefault("msg", exc)
            event.set()
        try:
            self._queue.put_nowait(_SESSION_FAILED)
        except queue.Full:
            pass

    def _close_conn(self):
        # Never under a send in flight: on USB the interface release kills the
        # bulk OUT transfer mid-frame, which libusb reports as NO_DEVICE.
        with self._send_lock:
            self.conn.close()

    def _process(self, msg):
        t = msg.get("t")
        if t == "state":
            self._apply_kv(self.state, self.state_meta, msg)
        elif t == "settings":
            self._apply_kv(self.settings, self.settings_meta, msg)
        elif t == "channels":
            for k, v in (msg.get("channels") or {}).items():
                self.channels[k] = v
            for k in msg.get("drop") or []:
                self.channels.pop(k, None)
                self.record_meta.pop(k, None)
                self._field_ids.pop(k, None)
                self.subscriptions.discard(k)
        elif t == "commands":
            for k, v in (msg.get("commands") or {}).items():
                self.commands[k] = v
            for k in msg.get("drop") or []:
                self.commands.pop(k, None)
        elif t == "control":
            self.control = msg
        elif t == "record_meta":
            ch = msg["channel"]
            self.record_meta[ch] = msg
            self._field_ids[ch] = {
                f["id"]: f for f in msg.get("fields", []) if _usable_field(f)
            }
        elif t == "record":
            return self._decode_record(msg)
        elif t == "ready":
            self.ready = True
        elif t == "reset":
            raise AirdaqError(
                "session reset by server: {}".format(msg.get("reason", "no reason"))
            )
        return msg

    def _apply_kv(self, values, meta, msg):
        # Overwrites apply before removals; meta first so a dtype arriving
        # in the same push coerces its own values.
        for k, m in (msg.get("meta") or {}).items():
            meta[k] = m
        for k, v in (msg.get("values") or {}).items():
            values[k] = _coerce_float(v, (meta.get(k) or {}).get("dtype"))
        for k in msg.get("drop_values") or []:
            values.pop(k, None)
        for k in msg.get("drop_meta") or []:
            meta.pop(k, None)

    def _decode_record(self, msg):
        fields = self._field_ids.get(msg.get("channel"), {})
        values = {}
        for fid, val in (msg.get("values") or {}).items():
            f = fields.get(fid)
            if f is None:
                values[fid] = val
            else:
                values[f["key"]] = _coerce_float(val, f.get("dtype"))
        msg["values"] = values
        return msg
