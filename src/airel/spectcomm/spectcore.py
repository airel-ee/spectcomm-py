import collections
import glob
import json
import os.path
import random
import select
import socket
import struct

import serial
from cobs import cobs


class SpectCoreRemoteError(Exception):
    pass


class SpectCoreSocketConnection:
    def __init__(
        self, address=None, port=55400, socket_path=None, username=None, password=None
    ):
        if address is None:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            if socket_path is None:
                potential_paths = glob.glob("/tmp/spectops-*")
                if len(potential_paths) == 0:
                    raise SpectCoreRemoteError("No sockets found.")

                times = [os.path.getmtime(x) for x in potential_paths]
                t = times[0]
                socket_path = potential_paths[0]
                for nt, np in zip(times, potential_paths):
                    if nt > t:
                        t = nt
                        socket_path = np

            self.socket.connect(socket_path)
        elif isinstance(address, str):
            self.socket = socket.create_connection((address, port))
        else:
            self.socket = socket.create_connection(address)
        self.socket.setblocking(True)

        protocolversion = bytearray()

        while True:
            b = self.socket.recv(1)
            protocolversion.append(b[0])
            if b == b"\n":
                break
            if len(protocolversion) > 20:
                raise SpectCoreRemoteError("Unknown response from device")

        if protocolversion == b"SRCP/4.0\r\n":
            self.protocol = 4
        elif protocolversion == b"SRCP/5.0\r\n":
            self.protocol = 5
        else:
            raise SpectCoreRemoteError(
                "Unsupported protocol version: {}".format(protocolversion)
            )

    def send_message(self, message):
        data = json.dumps(message)

        size = len(data)
        if size > 0xFFFF:
            raise SpectCoreRemoteError("Too long message")

        self.socket.sendall(size.to_bytes(2, "big"))
        self.socket.sendall(bytearray(data, "utf8"))

    def receive_message_raw(self, timeout=60):
        size = 0

        if not self.wait_for_recv(timeout):
            return None
        b = self.socket.recv(1)
        if len(b) == 0:
            raise SpectCoreRemoteError("Received no response")

        size = (ord(b) << 8) & 0xFF00

        self.wait_for_recv()
        b = self.socket.recv(1)
        size |= ord(b) & 0xFF

        data = bytearray(size)
        recvsize = 0

        while recvsize < size:
            self.wait_for_recv()
            x = self.socket.recv_into(memoryview(data)[recvsize:], size - recvsize)
            recvsize += x

        return data

    def wait_for_recv(self, timeout=60):
        ready_to_read, ready_to_write, in_error = select.select(
            [self.socket], [], [self.socket], timeout
        )
        if in_error:
            raise SpectCoreRemoteError("Socket failure")
        elif ready_to_read:
            return True
        else:
            return False


def connect_socket(
    address=None, port=55400, socket_path=None, username=None, password=None
):
    interface = SpectCoreSocketConnection(
        address, port, socket_path, username, password
    )
    return SpectCoreRemote(interface)


class SpectCoreRemote:
    def __init__(self, conn):
        self.conn = conn

        random.seed()

        self.message_queue = collections.deque()
        self.id_counter = 1
        self.flag_map = {}
        self._get_init_metadata()

    def send_message(self, message):
        self.conn.send_message(message)

    def receive_message(self, timeout=60):
        data = self.conn.receive_message_raw(timeout)
        if data is None:
            return None
        elif data[0] == 0x81:
            return self._process_binary_rec(data)
        else:
            return json.loads(str(data, "utf8"))

    def wait_for_recv(self, timeout=60):
        return self.conn.wait_for_recv(timeout)

    def _get_init_metadata(self):
        msgid = self.next_msg_id()
        msg = {"method": "get_metadata", "id": msgid}
        self.send_message(msg)
        res = self.receive_id_response(msgid)
        if "error" in res:
            raise SpectCoreRemoteError("Response error '{0}'".format(res["error"]))

        self._process_data_info(res["result"])

    def _process_data_info(self, msg):
        self.instrument_id = msg["instrument_id"]
        self.variable_list = msg["variables"]
        self.variables = {v["id"]: v for v in self.variable_list}
        self.opmode_list = msg["opmodes"]

    def set_stream(self, streams):
        msgid = self.next_msg_id()
        msg = {
            "method": "set_stream",
            "id": msgid,
            "params": {"streams": streams},
        }
        self.send_message(msg)

    def receive_id_response(self, id):
        for i, msg in enumerate(self.message_queue):
            if (
                ("id" in msg)
                and (("result" in msg) or ("error" in msg))
                and (msg["id"] == id)
            ):
                del self.message_queue[i]
                return msg

        while True:
            msg = self.receive_message()
            if msg is None:
                raise SpectCoreRemoteError("Connection timeout")
            if (
                ("id" in msg)
                and (("result" in msg) or ("error" in msg))
                and (msg["id"] == id)
            ):
                return msg
            else:
                self.message_queue.append(msg)

    def next_msg_id(self):
        self.id_counter += 1
        return self.id_counter

    def next_message(self, timeout=60):
        try:
            return self.message_queue.popleft()
        except IndexError:
            pass

        return self.receive_message(timeout)

    def set_pid_parameters(self, parameter, p, i, d, ctrl=None):
        if ctrl is None:
            self.execute_script(
                'set_pid_parameters("%s", %f, %f, %f)' % (parameter, p, i, d)
            )
        else:
            self.execute_script(
                'set_pid_parameters("%s", %f, %f, %f, %f)' % (parameter, p, i, d, ctrl)
            )

    def set_var(self, map):
        msgid = self.next_msg_id()
        msg = {"method": "set_var", "id": msgid, "params": map}
        self.send_message(msg)
        res = self.receive_id_response(msgid)
        if "error" in res:
            raise SpectCoreRemoteError("Response error '{0}'".format(res["error"]))
        return res

    def set_opmode(self, name):
        msgid = self.next_msg_id()
        msg = {
            "method": "set_opmode",
            "id": msgid,
            "params": {"name": name},
        }
        self.send_message(msg)
        res = self.receive_id_response(msgid)
        if "error" in res:
            raise SpectCoreRemoteError("Response error '{0}'".format(res["error"]))
        return res

    def request_control(self, priority=None):
        msgid = self.next_msg_id()
        if priority is None:
            params = {}
        else:
            params = {"priority": priority}
        msg = {"method": "request_control", "id": msgid, "params": params}
        self.send_message(msg)
        res = self.receive_id_response(msgid)
        if "error" in res:
            raise SpectCoreRemoteError("Response error '{0}'".format(res["error"]))
        return res

    def _process_binary_rec(self, buf):
        mv = memoryview(buf)

        pos = 1

        nanonowt = int.from_bytes(mv[pos : pos + 8], "little")
        pos += 8

        nanot = int.from_bytes(mv[pos : pos + 8], "little")
        pos += 8

        opmode = mv[pos]
        pos += 1

        devflags = mv[pos]
        is_valid = devflags & 1
        pos += 1

        bufsize = len(mv)

        rec = {
            "method": "raw_record",
            "nanot": nanot,
            "nanonowt": nanonowt,
            "opmode": opmode,
            "is_valid": is_valid,
        }

        while pos < bufsize:
            varnum = int.from_bytes(mv[pos : pos + 2], "little")
            var = self.variable_list[varnum]
            vecsize = var["size"]
            if vecsize == 1:
                val = struct.unpack_from("d", mv, pos + 2)[0]
            else:
                val = struct.unpack(
                    "{}d".format(vecsize), mv[pos + 2 : pos + 2 + 8 * vecsize]
                )
            pos += 2 + 8 * vecsize
            rec[var["id"]] = val

        return rec

    def set_var_params(self, name, params):
        msgid = self.next_msg_id()
        msg = {
            "method": "set_var_parameters",
            "id": msgid,
            "params": {"var": name, "params": params},
        }

        self.send_message(msg)
        res = self.receive_id_response(msgid)
        if "error" in res:
            raise SpectCoreRemoteError("Response error '{0}'".format(res["error"]))

    def send_script_message(self, name, data, destination=None, no_response=False):
        msgid = self.next_msg_id()
        msg = {
            "method": "message",
            "id": msgid,
            "params": {"name": name, "data": data, "destination": destination},
        }

        self.send_message(msg)
        if not no_response:
            res = self.receive_id_response(msgid)
            if "error" in res:
                raise SpectCoreRemoteError("Response error '{0}'".format(res["error"]))
