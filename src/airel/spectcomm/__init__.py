from .remote import SpectopsRemote, SpectopsRemoteError
from .spectcore import (
    connect_socket,
    SpectCoreRemote,
    SpectCoreRemoteError,
)
from .serial_connection import connect_serial_port
from . import airdaq
from .airdaq import AirdaqRemote, AirdaqError
