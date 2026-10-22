import collections
import threading
import time
from types import SimpleNamespace

import cbor2
import pytest
import usb.backend
import usb.core
from cobs import cobs

from airel.spectcomm.airdaq import (
    USB_PID,
    USB_SUBCLASS,
    USB_VID,
    AirdaqError,
    AirdaqRemote,
    AirdaqUsbConnection,
)

EP_OUT, EP_IN = 0x01, 0x81
EBUSY = 16

S_HELLO = {
    "t": "hello",
    "protocol": "airdaq",
    "version": 2,
    "capabilities": [],
    "device_id": "dmabox-1-9",
    "make": "Airel",
    "model": "dmabox-1",
    "sw_version": "0.2.0",
}


class FakeLibusb(usb.backend.IBackend):
    """One airdaq device behind libusb's handle rules: an interface claimed
    through one open handle is busy for every other, and closing a handle
    under a transfer in flight is recorded."""

    def __init__(self):
        self.cond = threading.Condition()
        self.handles = set()
        self.claims = {}
        self.transfers = collections.Counter()
        self.closed_under_transfer = False
        self.inbound = bytearray()
        self.outbound = bytearray()
        self.commands = []
        self.held = {}

    def push(self, msg):
        with self.cond:
            self.inbound += cobs.encode(cbor2.dumps(msg)) + b"\x00"
            self.cond.notify_all()

    def get_device_descriptor(self, dev):
        return SimpleNamespace(
            bLength=18, bDescriptorType=1, bcdUSB=0x200, bDeviceClass=0,
            bDeviceSubClass=0, bDeviceProtocol=0, bMaxPacketSize0=64,
            idVendor=USB_VID, idProduct=USB_PID, bcdDevice=0x100,
            iManufacturer=1, iProduct=2, iSerialNumber=3, bNumConfigurations=1,
            address=5, bus=1, port_number=1, port_numbers=(1,), speed=3,
        )  # fmt: skip

    def get_configuration_descriptor(self, dev, config):
        return SimpleNamespace(
            bLength=9, bDescriptorType=2, wTotalLength=32, bNumInterfaces=1,
            bConfigurationValue=1, iConfiguration=0, bmAttributes=0x80,
            bMaxPower=50, extra_descriptors=[],
        )  # fmt: skip

    def get_interface_descriptor(self, dev, intf, alt, config):
        if alt > 0:
            raise IndexError(alt)
        return SimpleNamespace(
            bLength=9, bDescriptorType=4, bInterfaceNumber=0, bAlternateSetting=0,
            bNumEndpoints=2, bInterfaceClass=0xFF, bInterfaceSubClass=USB_SUBCLASS,
            bInterfaceProtocol=2, iInterface=0, extra_descriptors=[],
        )  # fmt: skip

    def get_endpoint_descriptor(self, dev, ep, intf, alt, config):
        return SimpleNamespace(
            bLength=7, bDescriptorType=5, bEndpointAddress=(EP_OUT, EP_IN)[ep],
            bmAttributes=2, wMaxPacketSize=64, bInterval=0, bRefresh=0,
            bSynchAddress=0, extra_descriptors=[],
        )  # fmt: skip

    def open_device(self, dev):
        handle = object()
        with self.cond:
            self.handles.add(handle)
        return handle

    def close_device(self, handle):
        with self.cond:
            if self.transfers[handle]:
                self.closed_under_transfer = True
            self.handles.discard(handle)
            self.claims = {i: h for i, h in self.claims.items() if h is not handle}

    def get_configuration(self, handle):
        return 1

    def claim_interface(self, handle, intf):
        with self.cond:
            if self.claims.get(intf, handle) is not handle:
                raise usb.core.USBError("Resource busy", errno=EBUSY)
            self.claims[intf] = handle

    def release_interface(self, handle, intf):
        with self.cond:
            if self.claims.get(intf) is handle:
                del self.claims[intf]

    def bulk_write(self, handle, ep, intf, data, timeout):
        with self.cond:
            self.transfers[handle] += 1
        try:
            self.outbound += bytes(data)
            while (end := self.outbound.find(0)) >= 0:
                frame = bytes(self.outbound[:end])
                del self.outbound[: end + 1]
                if frame:
                    self.receive(cbor2.loads(cobs.decode(frame)))
            return len(data)
        finally:
            with self.cond:
                self.transfers[handle] -= 1

    def bulk_read(self, handle, ep, intf, buff, timeout):
        with self.cond:
            self.transfers[handle] += 1
            try:
                if not self.cond.wait_for(lambda: self.inbound, timeout / 1000):
                    raise usb.core.USBTimeoutError("Operation timed out", errno=110)
                n = min(len(buff), len(self.inbound))
                buff[:n] = type(buff)("B", self.inbound[:n])
                del self.inbound[:n]
                return n
            finally:
                self.transfers[handle] -= 1

    def receive(self, msg):
        if msg["t"] == "hello":
            self.push(S_HELLO | {"nonce": msg["nonce"]})
            self.push({"t": "ready"})
        elif msg["t"] == "command":
            held = self.held.get(msg["key"])
            if held is not None:
                held["writing"].set()
                held["release"].wait(timeout=5)
            self.commands.append(msg["key"])
            self.push({"t": "ok", "id": msg["id"], "result": None})


def open_session(lib):
    return AirdaqRemote(
        AirdaqUsbConnection(usb.core.Device("airdaq", lib)), client_name="t@h"
    )


def test_close_leaves_the_interface_free():
    lib = FakeLibusb()
    dev = open_session(lib)
    time.sleep(0.1)  # the reader waits in a bulk read
    dev.close()
    time.sleep(1.5)  # past a reader tick

    assert not lib.closed_under_transfer
    assert not lib.handles
    with open_session(lib) as again:
        assert again.ready


def test_no_send_follows_a_session_failure():
    lib = FakeLibusb()
    lib.held["slow"] = {"writing": threading.Event(), "release": threading.Event()}
    dev = open_session(lib)
    errors = {}

    def call(key):
        try:
            dev.command(key, timeout=5)
        except AirdaqError as e:
            errors[key] = str(e)

    slow = threading.Thread(target=call, args=("slow",))
    slow.start()
    assert lib.held["slow"]["writing"].wait(timeout=5)
    queued = threading.Thread(target=call, args=("queued",))
    queued.start()
    time.sleep(0.2)  # queued waits behind the slow send
    lib.push({"t": "reset", "reason": "idle_timeout"})
    with pytest.raises(AirdaqError, match="reset by server"):
        dev.next_message(timeout=5)
    lib.held["slow"]["release"].set()
    slow.join(timeout=5)
    queued.join(timeout=5)
    dev.close()

    assert lib.commands == ["slow"]
    assert errors["queued"] == "session reset by server: idle_timeout"
    assert not lib.handles


def test_a_failed_claim_closes_the_handle():
    lib = FakeLibusb()
    holder = AirdaqUsbConnection(usb.core.Device("airdaq", lib))
    device = usb.core.Device("airdaq", lib)
    with pytest.raises(usb.core.USBError, match="Resource busy"):
        AirdaqUsbConnection(device)

    assert len(lib.handles) == 1
    holder.close()
