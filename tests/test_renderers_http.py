"""The HTTP screen renderer, reached through ``--decode-as``.

The real capture (``http/http.pcap``, vendored with NETProtocols 2.9.0;
see fixtures/MANIFEST.md) carries the happy paths: curl's requests, a
304, a POST body, and three requests pipelined in one segment. Crafted
segments cover what it holds on purpose nowhere: framing anomalies a
request-smuggling attack rests on, chunked bodies and trailers, and
sender-chosen text carrying terminal escapes (C1) -- read as latin-1, a
lone 0x9B byte is a C1 CSI.
"""

from __future__ import annotations

import io

from netprotocols import HTTP

from conftest import FIXTURES, read_pcap
from rootwire.decoder import decode_frame, decode_options
from rootwire.output import _LIST_LIMIT, _TEXT_LIMIT, OutputToScreen
from test_renderers_tier_a import tcp_payload_frame

_PORT = 8080
_OPTIONS = decode_options({"tcp.port": {_PORT: HTTP, 80: HTTP}})

#: An ESC-led sequence that clears the screen, written as an escape.
_ESC = "\x1b[2J"


def render(data: bytes) -> str:
    """Screen rendering of *data* with HTTP read on ports 80 and 8080."""
    frame = decode_frame(
        data, number=1, timestamp=0, interface="eth0", options=_OPTIONS
    )
    stream = io.StringIO()
    OutputToScreen(display_payload=False, stream=stream).update(frame)
    return stream.getvalue()


def corpus(index: int) -> str:
    """The rendering of frame *index* of the HTTP capture."""
    return render(read_pcap(FIXTURES / "http" / "http.pcap")[index])


def message(raw: bytes) -> str:
    """The rendering of a TCP segment to port 8080 carrying *raw*,
    after checking that the walk decoded it as HTTP."""
    data = tcp_payload_frame(_PORT, raw)
    frame = decode_frame(
        data, number=1, timestamp=0, interface=None, options=_OPTIONS
    )
    assert frame.layer(HTTP) is not None, frame.error or frame.l7_miss
    return render(data)


def assert_escaped(text: str) -> None:
    """*text* holds no raw ESC or C1 CSI, and no forged line."""
    assert "\x1b" not in text
    assert "\x9b" not in text
    assert "\n[!]" not in text


# --- real capture ----------------------------------------------------------


def test_request_line_fields_and_body() -> None:
    """curl's GET: the start line, Host and User-Agent, every field by
    name, and no body."""
    text = corpus(3)
    assert "[+] HTTP GET /hello (HTTP/1.1)\n" in text
    assert "Host: 10.9.8.1\n" in text
    assert "User-Agent: curl/8.5.0\n" in text
    assert "Fields: Host, User-Agent, Accept\n" in text
    assert "Body: none\n" in text


def test_response_without_body() -> None:
    """A 304 shows its status, reason and Server."""
    text = corpus(27)
    assert "[+] HTTP 304 Not Modified (HTTP/1.1)\n" in text
    assert "Server: NETProtocols-fixture\n" in text
    assert "Fields: Server, Date, ETag\n" in text


def test_post_body_size_not_bytes() -> None:
    """A POST shows its Content-Type and its body's size, never the
    body itself."""
    text = corpus(35)
    assert "[+] HTTP POST /echo (HTTP/1.1)" in text
    assert "Content-Type: application/x-www-form-urlencoded\n" in text
    assert "Body: 17 bytes (content_length)\n" in text


def test_pipelined_requests_are_counted() -> None:
    """Three requests in one segment: the first renders, and the bytes
    of the other two are counted, not lost."""
    text = corpus(77)
    assert "[+] HTTP GET /hello (HTTP/1.1)" in text
    assert "[~] 100 more bytes follow this message" in text


def test_segment_that_is_not_a_message_is_a_miss() -> None:
    """A response body in a segment of its own is a best-effort miss."""
    text = corpus(7)
    assert "[~] Payload left undecoded: " in text
    assert "[+] HTTP" not in text
    assert "[!]" not in text


# --- crafted ---------------------------------------------------------------


def test_chunked_response_with_trailer() -> None:
    """A chunked body's size is the content's, its trailer counted, and
    an empty reason phrase leaves no gap."""
    raw = (
        b"HTTP/1.1 200 \r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n0\r\nX-Checksum: 1\r\n\r\n"
    )
    text = message(raw)
    assert "[+] HTTP 200 (HTTP/1.1)\n" in text
    assert "Body: 5 bytes (chunked), 1 trailer field\n" in text


def test_smuggling_anomalies_are_flagged() -> None:
    """Content-Length with Transfer-Encoding and a second Host are the
    stuff of request smuggling: flagged, in wire order."""
    raw = (
        b"POST / HTTP/1.1\r\nHost: a\r\nHost: b\r\nContent-Length: 3\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    )
    text = message(raw)
    assert (
        "[!] Framing anomalies: host_duplicate (host), "
        "cl_and_te (content-length)\n"
    ) in text
    assert "Host: a\n" in text
    assert "Host: b\n" in text


def test_other_anomalies_are_noted() -> None:
    """An anomaly that does not bear on framing is a [~] note."""
    text = message(b"GET / HTTP/1.1\r\nHost: a\r\nX-A: one\r\n two\r\n\r\n")
    assert "[~] Anomalies: obs_fold (x-a)" in text
    assert "[!] Framing" not in text


def test_target_and_field_values_are_sanitized() -> None:
    """C1: the request-target, a field value and a field name are the
    sender's; ESC and a C1 CSI reach the terminal escaped."""
    raw = (
        f"GET /{_ESC} HTTP/1.1\r\nHost: a\r\nUser-Agent: x\x9b2J\r\n"
        f"X-{_ESC}: v\r\n\r\n"
    ).encode("latin-1")
    text = message(raw)
    assert_escaped(text)
    assert "[+] HTTP GET /\\x1b[2J (HTTP/1.1)" in text
    assert "User-Agent: x\\x9b2J\n" in text
    assert "X-\\x1b[2J" in text


def test_reason_phrase_is_sanitized() -> None:
    """C1: a reason phrase carrying a C1 CSI stays escaped."""
    text = message(b"HTTP/1.1 404 Gone\x9b2J\r\nContent-Length: 0\r\n\r\n")
    assert_escaped(text)
    assert "[+] HTTP 404 Gone\\x9b2J (HTTP/1.1)" in text


def test_long_target_is_cut() -> None:
    """A request-target is cut at the text limit."""
    target = b"/" + b"a" * (_TEXT_LIMIT + 7)
    text = message(b"GET " + target + b" HTTP/1.1\r\nHost: a\r\n\r\n")
    assert f"GET /{'a' * (_TEXT_LIMIT - 1)}... (+8 more chars)" in text


def test_fields_line_is_capped() -> None:
    """More fields than the list limit are capped."""
    fields = b"".join(b"X-%d: 1\r\n" % n for n in range(_LIST_LIMIT + 4))
    text = message(b"GET / HTTP/1.1\r\nHost: a\r\n" + fields + b"\r\n")
    assert "(+5 more)" in text
