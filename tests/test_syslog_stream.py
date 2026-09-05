import socket

import pytest

from vendor.syslog_stream import SyslogFrameError, iter_syslog_frames


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
