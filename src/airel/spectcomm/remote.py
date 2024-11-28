import collections
import glob
import json
import os.path
import select
import socket


class SpectopsRemoteError(Exception):
    pass


class SpectopsRemote:
    def __init__(self, address=None, socket_path=None, username=None, password=None):
        try:
            if address is None:
                self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                if socket_path is None:
                    potential_paths = glob.glob("/tmp/spectops-*")
                    if len(potential_paths) == 0:
                        raise SpectopsRemoteError("No sockets found.")
                    elif len(potential_paths) > 1:
                        raise SpectopsRemoteError(
                            f"Found several Spectops sockets: {potential_paths}"
                        )

                    times = [os.path.getmtime(x) for x in potential_paths]
                    t = times[0]
                    socket_path = potential_paths[0]
                    for nt, np in zip(times, potential_paths):
                        if nt > t:
                            t = nt
                            socket_path = np

                self.socket.connect(socket_path)
            else:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect(address)
            self.socket.setblocking(True)

            protocolversion = self.socket.recv(100)
            if protocolversion != b"SORCP/4.0\r\n":
                raise SpectopsRemoteError(
                    "Unsupported protocol version {}".format(repr(protocolversion))
                )

            if address is not None:
                self._login(username, password)

            self.send_message({"method": "get_data_info", "params": {}})

            message = self.receive_message()

            if "challenge" in message:
                self._login(message, username, password)
            else:
                self._process_data_info(message["result"])

            self.message_queue = collections.deque()

            self.id_counter = 1

            self.flag_map = {}
        except ConnectionError as e:
            raise SpectopsRemoteError(e) from e
        except FileNotFoundError as e:
            raise SpectopsRemoteError(e) from e

    def send_message(self, message):
        data = json.dumps(message).encode("utf-8")

        size = len(data)
        if size > 0xFFFF:
            raise SpectopsRemoteError("Too long message")

        self.socket.sendall(bytes([((size & 0xFF00) >> 8), (size & 0xFF)]))
        self.socket.sendall(data)

    def receive_message(self, timeout=60):
        size = 0

        if not self.wait_for_recv(timeout):
            return None
        b = self.socket.recv(1)
        if len(b) == 0:
            raise SpectopsRemoteError("Received no response")

        size = (ord(b) << 8) & 0xFF00

        self.wait_for_recv()
        b = self.socket.recv(1)
        size |= ord(b) & 0xFF

        message = bytearray()
        recvsize = 0

        while recvsize < size:
            self.wait_for_recv()
            x = self.socket.recv(size - recvsize)
            if len(x):
                message += x
                recvsize += len(x)

        return json.loads(message.decode("utf-8"))

    def wait_for_recv(self, timeout=60):
        ready_to_read, ready_to_write, in_error = select.select(
            [self.socket], [], [self.socket], timeout
        )
        if in_error:
            raise SpectopsRemoteError("Socket failure")
        elif ready_to_read:
            return True
        else:
            return False

    def _login(self, username, password):
        params = {"password": password}
        if username is not None:
            params["username"] = username

        send_msg = {
            "method": "login",
            "params": params,
        }

        self.send_message(send_msg)

        recv_msg = self.receive_message()
        if recv_msg.get("result") == "success":
            return

        try:
            error = recv_msg["error"]["message"]
        except KeyError:
            raise SpectopsRemoteError("Invalid message received")

        raise SpectopsRemoteError(f"Login faillure: {repr(error)}")

    def _process_data_info(self, msg):
        self.diagnostic_parameter_list = msg.get("instrument_variables", [])
        self.diagnostic_parameter_index = {}
        for i, p in enumerate(self.diagnostic_parameter_list):
            self.diagnostic_parameter_index[p["id"]] = i

        self.opmode_list = msg.get("opmodes", [])
        self.opmode_index = {op["id"]: op for op in self.opmode_list}

        self.dataproc_variants = msg.get("dataproc_variants", [])

        self.electrometer_names = msg.get("electrometer_names", [])
        self.electrometer_groups = msg.get("electrometer_groups", [])

    def set_streams(self, streams):
        msg = {"method": "set_streams", "params": streams}
        self.send_message(msg)

    def set_stream_settings(self, rawdata=None, avgdata=None):
        args = {}

        if rawdata is not None:
            args["stream_raw_data"] = bool(rawdata)
        if avgdata is not None:
            args["stream_avg_data"] = bool(avgdata)

        msg = {"method": "set_stream_settings", "params": args}

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
                raise SpectopsRemoteError("Connection timeout")
            if (
                ("id" in msg)
                and (("result" in msg) or ("error" in msg))
                and (msg["id"] == id)
            ):
                return msg
            else:
                self.message_queue.append(msg)

    def execute_script(self, script):
        msg = {"method": "execute_script", "params": {"script": script}}
        self.send_message(msg)
        return id

    def next_msg_id(self):
        self.id_counter += 1
        return self.id_counter

    def execute_script_ret(self, script):
        msgid = self.next_msg_id()

        msg = {"method": "execute_script", "params": {"script": script}, "id": msgid}
        self.send_message(msg)
        res = self.receive_id_response(msgid)
        if "error" in res:
            raise SpectopsRemoteError("Response error '{0}'".format(res["error"]))
        else:
            return res["result"]

    def next_message(self, timeout=60):
        try:
            return self.message_queue.popleft()
        except IndexError:
            return self.receive_message(timeout)
