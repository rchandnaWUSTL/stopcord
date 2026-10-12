"""Loaded via PYTHONPATH in tests: refuse any socket connection that isn't loopback or unix."""
import socket

_connect = socket.socket.connect


def _guarded(self, address):
    if self.family == socket.AF_UNIX:
        return _connect(self, address)
    host = address[0] if isinstance(address, tuple) else address
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise OSError(f"network blocked in test: {address}")
    return _connect(self, address)


socket.socket.connect = _guarded
