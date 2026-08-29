"""NDJSON output and capture statistics."""

import io
import json

from conftest import FIXTURES
from rootwire import cli
from rootwire.decoder import decode_frame
from rootwire.output import OutputToNDJSON, StatsCollector

SCHEMA_KEYS = {
    "number",
    "timestamp",
    "interface",
    "length",
    "truncated",
    "error",
    "payload_len",
    "layers",
}


def emit(data: bytes) -> dict:
    stream = io.StringIO()
    OutputToNDJSON(stream).update(
        decode_frame(data, number=7, timestamp=1_787_000_000.5, interface="x")
    )
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert isinstance(parsed, dict)
    return parsed


class TestOutputToNDJSON:
    def test_schema_keys_and_metadata(self, arp_frame):
        record = emit(arp_frame)
        assert set(record) == SCHEMA_KEYS
        assert record["number"] == 7
        assert record["interface"] == "x"
        assert record["length"] == len(arp_frame)
        assert record["error"] is None

    def test_layer_fields_with_hex_encoded_bytes(self, tcp_frame_with_options):
        record = emit(tcp_frame_with_options)
        types = [layer["type"] for layer in record["layers"]]
        assert types == ["Ethernet", "IPv4", "TCP"]
        tcp = record["layers"][2]
        assert tcp["src_port"] == 51888
        assert tcp["options"] == "0101080a0008ca610001692e"
        assert record["payload_len"] == 16  # "GET / HTTP/1.1\r\n"

    def test_every_corpus_frame_serializes(self):
        from conftest import corpus_frames

        for _, _, frame in corpus_frames():
            emit(frame)


class TestStatsCollector:
    def collect(self, frames: list[bytes]) -> StatsCollector:
        stats = StatsCollector()
        for number, data in enumerate(frames, start=1):
            stats.update(
                decode_frame(data, number=number, timestamp=0.0, interface=None)
            )
        return stats

    def test_buckets_by_innermost_known_layer(self, arp_frame, udp_frame):
        from netprotocols import IPv6Fragment

        from conftest import read_pcap

        mld = read_pcap(FIXTURES / "ipv6_mld.pcap")[0]
        fragment_non_first = next(
            data
            for data in read_pcap(FIXTURES / "ipv6_fragments.pcap")
            if (
                lambda frame: (
                    isinstance(frame.layers[-1], IPv6Fragment)
                    and frame.layers[-1].fragment_offset > 0
                )
            )(decode_frame(data, number=1, timestamp=0.0, interface=None))
        )
        stats = self.collect([arp_frame, udp_frame, mld, fragment_non_first])
        stream = io.StringIO()
        stats.report(stream)
        text = stream.getvalue()
        assert "4 frames" in text
        assert "ARP: 1" in text
        assert "UDP: 1" in text
        assert "ICMPv6: 1" in text  # MLD's innermost layer is ICMPv6
        assert "other: 1" in text  # non-first fragment ends at the header

    def test_malformed_and_truncated_counters(self, truncated_frame):
        stats = self.collect([truncated_frame])
        stream = io.StringIO()
        stats.report(stream)
        assert "malformed: 1, truncated: 1" in stream.getvalue()


class TestJSONModePurity:
    def test_stdout_carries_nothing_but_ndjson(self, capsys):
        source = FIXTURES / "udp_dns.pcap"
        assert cli.main(["-r", str(source), "--json"]) == 0
        captured = capsys.readouterr()
        lines = captured.out.splitlines()
        assert lines
        for line in lines:
            json.loads(line)  # every stdout line must be JSON
        assert "[>>>]" in captured.err  # banner on stderr
        assert "frames/s" in captured.err  # stats on stderr

    def test_json_composes_with_write(self, tmp_path, capsys):
        from rootwire.pcap import read_pcap as replay

        source = FIXTURES / "arp_exchange.pcap"
        copy = tmp_path / "copy.pcap"
        assert cli.main(["-r", str(source), "--json", "-w", str(copy)]) == 0
        for line in capsys.readouterr().out.splitlines():
            json.loads(line)
        assert len(list(replay(copy))) == 4

    def test_screen_mode_reports_stats_on_stderr_too(self, capsys):
        assert cli.main(["-r", str(FIXTURES / "arp_exchange.pcap")]) == 0
        captured = capsys.readouterr()
        assert "Frame #" in captured.out
        assert "frames/s" in captured.err
