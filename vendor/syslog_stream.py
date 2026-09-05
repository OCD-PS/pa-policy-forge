"""Bounded TCP syslog stream framing for RFC 6587 clients."""

from __future__ import annotations

import socket
import socketserver
import threading
from collections.abc import Callable, Iterator


class SyslogFrameError(ValueError):
    """Raised when a TCP syslog frame violates the configured limits."""


def iter_syslog_frames(
    connection: socket.socket,
    *,
    max_message_bytes: int,
    read_size: int = 65536,
) -> Iterator[bytes]:
    """Yield RFC 6587 octet-counted or newline-delimited messages."""
    buffer = bytearray()
    while True:
        chunk = connection.recv(min(read_size, max_message_bytes + 32))
        if not chunk:
            if buffer:
                if len(buffer) > max_message_bytes:
                    raise SyslogFrameError("unterminated syslog frame exceeds limit")
                yield bytes(buffer).rstrip(b"\r")
            return
        buffer.extend(chunk)

        while buffer:
            space = buffer.find(b" ")
            newline = buffer.find(b"\n")
            if space > 0 and bytes(buffer[:space]).isdigit():
                if space > 20:
                    raise SyslogFrameError("invalid octet-count prefix")
                length = int(buffer[:space])
                if length <= 0 or length > max_message_bytes:
                    raise SyslogFrameError("octet-counted syslog frame exceeds limit")
                frame_end = space + 1 + length
                if len(buffer) < frame_end:
                    if len(buffer) > max_message_bytes + space + 1:
                        raise SyslogFrameError("octet-counted syslog frame exceeds limit")
                    break
                yield bytes(buffer[space + 1 : frame_end])
                del buffer[:frame_end]
                if buffer[:1] == b"\n":
                    del buffer[:1]
                continue

            if newline >= 0:
                if newline > max_message_bytes:
                    raise SyslogFrameError("newline-framed syslog message exceeds limit")
                frame = bytes(buffer[:newline]).rstrip(b"\r")
                del buffer[: newline + 1]
                if frame:
                    yield frame
                continue

            if len(buffer) > max_message_bytes:
                raise SyslogFrameError("unterminated syslog frame exceeds limit")
            break


def tcp_server(
    bind: tuple[str, int],
    callback: Callable[[bytes, str], None],
    *,
    max_message_bytes: int,
    connection_timeout: int,
    max_connections: int,
) -> socketserver.ThreadingTCPServer:
    """Create a bounded threaded TCP server using the shared ingest callback."""

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(connection_timeout)
            try:
                for frame in iter_syslog_frames(
                    self.request, max_message_bytes=max_message_bytes
                ):
                    callback(frame, self.client_address[0])
            except (TimeoutError, socket.timeout, SyslogFrameError, OSError):
                return

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        request_queue_size = max(16, max_connections)

        def __init__(self, server_address, handler_class):
            self._slots = threading.BoundedSemaphore(max_connections)
            super().__init__(server_address, handler_class)

        def process_request(self, request, client_address):
            if not self._slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except Exception:
                self._slots.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                self._slots.release()

    return Server(bind, Handler)
