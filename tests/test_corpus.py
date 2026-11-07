"""The real-capture corpus through the full application pipeline.

Every corpus frame (see tests/fixtures/MANIFEST.md; captured and
checksum-validated in the NETProtocols repository) must decode and
render without error — the sniffer's whole job, exercised on real
traffic instead of synthetic frames.
"""

import io

import pytest
from netprotocols import IPv4

from conftest import corpus_frames
from rootwire.decoder import decode_frame
from rootwire.output import OutputToScreen

CORPUS = corpus_frames()


def corpus_ids() -> list[str]:
    return [f"{name}#{index}" for name, index, _ in CORPUS]


@pytest.mark.parametrize("frame", [f for _, _, f in CORPUS], ids=corpus_ids())
class TestCorpusThroughPipeline:
    def test_decodes_cleanly(self, frame):
        decoded = decode_frame(frame, number=1, timestamp=0, interface="corpus")
        assert decoded.layers  # at least Ethernet
        assert decoded.error is None
        assert not decoded.truncated

    def test_renders_without_raising(self, frame):
        decoded = decode_frame(frame, number=1, timestamp=0, interface="corpus")
        stream = io.StringIO()
        OutputToScreen(display_payload=True, stream=stream).update(decoded)
        assert "Frame #1" in stream.getvalue()


class TestFragmentRendering:
    def test_non_first_fragments_render_as_ipv4_plus_payload(self):
        """Regression companion to the library's fragment fix: the
        payload of a non-first fragment must not be presented as a
        decoded upper-layer protocol."""
        fragment_frames = [
            frame for name, _, frame in CORPUS if name == "ipv4_fragments.pcap"
        ]
        assert fragment_frames
        saw_non_first = False
        for frame in fragment_frames:
            decoded = decode_frame(
                frame, number=1, timestamp=0, interface="corpus"
            )
            ip = decoded.layer(IPv4)
            assert ip is not None
            if ip.fragment_offset > 0:
                saw_non_first = True
                assert type(decoded.layers[-1]) is IPv4
                assert decoded.payload
        assert saw_non_first


class TestBestEffortMissesInRealTraffic:
    """The session captures hold every frame of real BGP/TLS/STUN
    sessions -- bare ACKs, FINs, records split across segments, RFC 3489
    messages the STUN decoder rejects. Each must be a best-effort miss,
    never an error: the real-traffic face of the rule
    tests/test_netprotocols_29.py pins synthetically."""

    @pytest.mark.parametrize(
        ("capture", "minimum_misses", "some_decode_whole"),
        [
            ("bgp_session.pcap", 50, True),
            ("tls_session.pcap", 60, True),
            # Every RFC 3489 message is rejected at the magic cookie, so
            # this capture is nothing but misses, by design.
            ("stun_rfc3489.pcap", 4, False),
            ("tcp_https.pcap", 5, True),
        ],
    )
    def test_session_capture_misses_without_errors(
        self, capture, minimum_misses, some_decode_whole
    ):
        """Every frame of the capture decodes with no error, at least
        *minimum_misses* of them as best-effort misses, and (where the
        capture holds whole messages) some still decode beyond TCP/UDP."""
        frames = [frame for name, _, frame in CORPUS if name == capture]
        assert frames
        decoded = [
            decode_frame(frame, number=1, timestamp=0, interface="corpus")
            for frame in frames
        ]
        assert all(frame.error is None for frame in decoded)
        misses = sum(frame.l7_miss is not None for frame in decoded)
        assert misses >= minimum_misses
        # Misses must not be all there is: the frames holding whole
        # messages still decode them.
        assert some_decode_whole == any(
            frame.l7_miss is None and len(frame.layers) > 3 for frame in decoded
        )

    def test_tls_session_still_decodes_whole_records(self):
        """Frame 39 holds whole TLS records; it decodes to a TLS layer
        rather than being swallowed by the miss rule."""
        frames = [f for name, _, f in CORPUS if name == "tls_session.pcap"]
        decoded = decode_frame(
            frames[39], number=1, timestamp=0, interface="corpus"
        )
        assert type(decoded.layers[-1]).__name__ == "TLS"
        assert decoded.l7_miss is None
