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
from packet_sniffer.decoder import decode_frame
from packet_sniffer.output import OutputToScreen

CORPUS = corpus_frames()


def corpus_ids() -> list[str]:
    return [f"{name}#{index}" for name, index, _ in CORPUS]


@pytest.mark.parametrize("frame", [f for _, _, f in CORPUS], ids=corpus_ids())
class TestCorpusThroughPipeline:
    def test_decodes_cleanly(self, frame):
        decoded = decode_frame(
            frame, number=1, timestamp=0.0, interface="corpus"
        )
        assert decoded.layers  # at least Ethernet
        assert decoded.error is None
        assert not decoded.truncated

    def test_renders_without_raising(self, frame):
        decoded = decode_frame(
            frame, number=1, timestamp=0.0, interface="corpus"
        )
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
                frame, number=1, timestamp=0.0, interface="corpus"
            )
            ip = decoded.layer(IPv4)
            assert ip is not None
            if ip.fragment_offset > 0:
                saw_non_first = True
                assert type(decoded.layers[-1]) is IPv4
                assert decoded.payload
        assert saw_non_first
