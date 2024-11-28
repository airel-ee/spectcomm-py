import binascii
import json
import select

import serial

from cobs import cobs

from .spectcore import SpectCoreRemoteError, SpectCoreRemote


def update_checksum(crc, data):
    for byte in data:
        crc = crc ^ (byte << 8)

        for i in range(8):
            if crc & 0x8000 != 0:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF

    return crc


def decode(packet: bytes) -> bytes:
    if len(packet) == 0:
        return b""

    try:
        contents = cobs.decode(packet)
    except cobs.DecodeError as e:
        raise SpectCoreRemoteError(
            "decoding error", str(e), binascii.b2a_qp(packet).decode("latin1")
        )

    if len(contents) < 2:
        raise SpectCoreRemoteError("packet too short")

    crc = update_checksum(0, contents[:-2])
    crc_bytes = crc.to_bytes(2, "little")
    if crc_bytes != contents[-2:]:
        raise SpectCoreRemoteError("invalid crc")

    return contents[:-2]


def encode(payload: bytes) -> bytes:
    if len(payload) == 0:
        return b""
    crc = update_checksum(0, payload)
    return cobs.encode(payload + crc.to_bytes(2, "little"))


class SpectCoreSerialConnection:
    def __init__(self, path):
        self.port = serial.Serial(path)
        self.port.timeout = 0.5
        self.buf = bytearray()

        for i in range(5):
            self.port.write(b"\x00x\x00")
            buf = self.port.read_until(b"\x00")
            if buf:
                try:
                    self.introduction_message = json.loads(decode(buf[:-1]))
                    return
                except json.JSONDecodeError:
                    continue
                break

        raise SpectCoreRemoteError("no response from device")

    def send_message(self, message):
        data = json.dumps(message)
        raw = encode(bytearray(data, "utf8")) + b"\x00"
        self.port.write(raw)

    def receive_message_raw(self, timeout=60):
        size = 0

        self.port.timeout = timeout
        self.buf += self.port.read_until(b"\x00")
        if not self.buf.endswith(b"\x00"):
            raise SpectCoreRemoteError("Received no response")

        data = decode(self.buf[:-1])

        self.buf.clear()

        return data

    def wait_for_recv(self, timeout=60):
        self.port.timeout = timeout
        data = self.port.read_until(b"\x00")
        self.buf += data
        return len(data) != 0


def connect_serial_port(path):
    interface = SpectCoreSerialConnection(path)
    remote = SpectCoreRemote(interface)
    remote.message_queue.append(interface.introduction_message)
    return remote
