"""pcap writing and replay: format goldens, round trips, and the whole
corpus through the file-replay pipeline."""

import struct

import pytest

from conftest import FIXTURES, corpus_frames
from rootwire import cli
from rootwire.decoder import decode_frame
from rootwire.output import Output, OutputToPcap
from rootwire.pcap import PcapWriter, read_pcap

FRAMES = [
    b"\xff" * 6 + b"\x00" * 6 + b"\x08\x06" + b"arp-ish",
    b"\x00" * 14,
]
TIMESTAMPS = [1_787_000_000.123456, 1_787_000_000.999999]


class TestWriterFormat:
    def test_global_header_golden_bytes(self, tmp_path):
        path = tmp_path / "empty.pcap"
        PcapWriter(path).close()
        assert path.read_bytes() == struct.pack(
            "<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_550, 1
        )

    def test_record_headers_carry_exact_microseconds(self, tmp_path):
        path = tmp_path / "two.pcap"
        with PcapWriter(path) as writer:
            for frame, timestamp in zip(FRAMES, TIMESTAMPS, strict=True):
                writer.write(frame, timestamp)
        data = path.read_bytes()
        cursor = 24
        seen = []
        for frame in FRAMES:
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(
                "<IIII", data, cursor
            )
            assert incl_len == orig_len == len(frame)
            seen.append((ts_sec, ts_usec))
            cursor += 16 + incl_len
        # Integer comparison: float µs at 2026 epoch values is lossy.
        assert seen[0] == (1_787_000_000, 123456)
        assert seen[1] == (1_787_000_000, 999999)

    def test_microsecond_rounding_carries_into_the_next_second(self, tmp_path):
        path = tmp_path / "carry.pcap"
        with PcapWriter(path) as writer:
            writer.write(b"x" * 14, 1_787_000_000.9999999)
        ts_sec, ts_usec = struct.unpack_from("<II", path.read_bytes(), 24)
        assert (ts_sec, ts_usec) == (1_787_000_001, 0)


class TestReader:
    def test_write_read_round_trip(self, tmp_path):
        path = tmp_path / "roundtrip.pcap"
        with PcapWriter(path) as writer:
            for frame, timestamp in zip(FRAMES, TIMESTAMPS, strict=True):
                writer.write(frame, timestamp)
        replayed = list(read_pcap(path))
        assert [frame for frame, _ in replayed] == FRAMES

    def test_big_endian_and_nanosecond_magic(self, tmp_path):
        for magic, divisor, name in (
            (0xA1B2C3D4, 1_000_000, "be-us"),
            (0xA1B23C4D, 1_000_000_000, "be-ns"),
        ):
            path = tmp_path / f"{name}.pcap"
            frame = FRAMES[0]
            path.write_bytes(
                struct.pack(">IHHiIII", magic, 2, 4, 0, 0, 65_550, 1)
                + struct.pack(
                    ">IIII",
                    1_787_000_000,
                    divisor // 2,
                    len(frame),
                    len(frame),
                )
                + frame
            )
            ((replayed, timestamp),) = list(read_pcap(path))
            assert replayed == frame
            assert timestamp == pytest.approx(1_787_000_000.5)

    def test_non_ethernet_linktype_rejected(self, tmp_path):
        path = tmp_path / "raw-ip.pcap"
        path.write_bytes(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_550, 101)
        )
        with pytest.raises(ValueError, match="linktype 101"):
            list(read_pcap(path))

    def test_not_a_pcap_rejected(self, tmp_path):
        path = tmp_path / "not.pcap"
        path.write_bytes(b"PK\x03\x04 definitely a zip" + b"\x00" * 16)
        with pytest.raises(ValueError, match="not a classic pcap"):
            list(read_pcap(path))

    def test_truncated_record_diagnosed(self, tmp_path):
        path = tmp_path / "cut.pcap"
        with PcapWriter(path) as writer:
            writer.write(FRAMES[0], TIMESTAMPS[0])
        path.write_bytes(path.read_bytes()[:-4])
        with pytest.raises(ValueError, match="truncated"):
            list(read_pcap(path))


class TestCorpusReplay:
    def test_every_corpus_pcap_replays_through_the_pipeline(self):
        """read_pcap must agree with the independent test reader and
        feed the decoder cleanly — the corpus doubles as the replay
        golden set."""
        expected = {}
        for name, _, frame in corpus_frames():
            expected.setdefault(name, []).append(frame)
        for pcap in sorted(FIXTURES.glob("*.pcap")):
            replayed = list(read_pcap(pcap))
            assert [f for f, _ in replayed] == expected[pcap.name]
            for number, (data, timestamp) in enumerate(replayed, start=1):
                frame = decode_frame(
                    data,
                    number=number,
                    timestamp=timestamp,
                    interface=str(pcap),
                )
                assert frame.layers
                assert frame.raw == data


class TestCaptureToPcapOutput:
    def test_output_writes_frames_byte_exactly(self, tmp_path, arp_frame):
        path = tmp_path / "out.pcap"
        output: Output = OutputToPcap(str(path))
        frame = decode_frame(
            arp_frame, number=1, timestamp=TIMESTAMPS[0], interface=None
        )
        output.update(frame)
        output.close()
        ((replayed, _),) = list(read_pcap(path))
        assert replayed == arp_frame


class TestCLIReplay:
    def test_replay_needs_no_root_and_reports_frames(self, tmp_path, capsys):
        source = FIXTURES / "arp_exchange.pcap"
        assert cli.main(["-r", str(source)]) == 0
        captured = capsys.readouterr()
        assert "Replaying" in captured.err
        assert "Frame #" in captured.out

    def test_replay_transform_copy(self, tmp_path, capsys):
        source = FIXTURES / "udp_dns.pcap"
        copy = tmp_path / "copy.pcap"
        assert cli.main(["-r", str(source), "-w", str(copy)]) == 0
        assert [f for f, _ in read_pcap(copy)] == [
            f for f, _ in read_pcap(source)
        ]

    def test_read_and_interface_are_exclusive(self):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["-r", "x.pcap", "-i", "eth0"])
        assert excinfo.value.code == 2

    def test_unreadable_pcap_is_a_clean_error(self, tmp_path, capsys):
        bad = tmp_path / "bad.pcap"
        bad.write_bytes(b"nonsense" * 4)
        assert cli.main(["-r", str(bad)]) == 1
        assert "Error:" in capsys.readouterr().err
