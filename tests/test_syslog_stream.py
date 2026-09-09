import socket
import threading
import time

import pytest

from vendor.syslog_stream import SyslogFrameError, iter_syslog_frames, udp_server


class ChunkSocket:
    def __init__(self, *chunks: bytes):
        self.chunks = iter((*chunks, b""))

    def recv(self, _size: int) -> bytes:
        return next(self.chunks)


def test_octet_counted_frames_across_reads():
    first = b"<14>one"
    second = b"<14>two"
    stream = f"{len(first)} ".encode() + first + f"{len(second)} ".encode() + second
    frames = list(iter_syslog_frames(ChunkSocket(stream[:5], stream[5:]), max_message_bytes=64))
    assert frames == [first, second]


def test_newline_frames_across_reads():
    frames = list(iter_syslog_frames(ChunkSocket(b"<14>one\r\n<14>", b"two\n"), max_message_bytes=64))
    assert frames == [b"<14>one", b"<14>two"]


def test_unterminated_last_frame_is_accepted_on_close():
    assert list(iter_syslog_frames(ChunkSocket(b"<14>one"), max_message_bytes=64)) == [b"<14>one"]


def test_oversized_octet_count_is_rejected():
    with pytest.raises(SyslogFrameError):
        list(iter_syslog_frames(ChunkSocket(b"100 payload"), max_message_bytes=64))


def test_oversized_newline_frame_is_rejected():
    with pytest.raises(SyslogFrameError):
        list(iter_syslog_frames(ChunkSocket(b"x" * 65 + b"\n"), max_message_bytes=64))


def test_socket_timeout_is_not_swallowed_by_framer():
    class TimeoutSocket:
        def recv(self, _size: int) -> bytes:
            raise socket.timeout

    with pytest.raises(socket.timeout):
        list(iter_syslog_frames(TimeoutSocket(), max_message_bytes=64))


def test_udp_server_bounds_concurrent_handlers():
    entered = threading.Event()
    release = threading.Event()
    received = []

    def callback(payload, _source):
        received.append(payload)
        entered.set()
        release.wait(1)

    server = udp_server(("127.0.0.1", 0), callback, max_workers=1)
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        client.sendto(b"first", server.server_address)
        assert entered.wait(1)
        client.sendto(b"dropped-while-busy", server.server_address)
        time.sleep(0.1)
        assert received == [b"first"]
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        client.close()
