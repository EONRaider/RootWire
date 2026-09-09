"""pcap writing and replay: format goldens, round trips, and the whole
corpus through the file-replay pipeline."""

import struct

import pytest

from conftest import FIXTURES, corpus_frames
from rootwire import cli
from rootwire.decoder import decode_frame
from rootwire.output import Output, OutputToPcap
from rootwire.pcap import PcapWriter, read_captures

FRAMES = [
    b"\xff" * 6 + b"\x00" * 6 + b"\x08\x06" + b"arp-ish",
    b"\x00" * 14,
]
#: Full nanosecond precision (not just microsecond-aligned), so the
#: golden tests below actually exercise the precision SO_TIMESTAMPNS
#: provides rather than a value that would look the same at either
#: resolution.
TIMESTAMPS = [1_787_000_000_123_456_789, 1_787_000_000_999_999_999]


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    """One little-endian pcapng block: type, total length, the body
    padded to a 4-byte boundary, then the total length again (every
    pcapng block shares this framing, per the format's spec)."""
    padded = body + b"\x00" * ((-len(body)) % 4)
    length = 12 + len(padded)
    return (
        struct.pack("<II", block_type, length)
        + padded
        + struct.pack("<I", length)
    )


def _build_pcapng(
    frames: list[tuple[bytes, int]], *, linktype: int = 1
) -> bytes:
    """A minimal little-endian pcapng capture: one Section Header
    Block, one Interface Description Block declaring ``if_tsresol`` as
    nanoseconds (so the timestamps below round-trip exactly, no
    resolution scaling to reason about), and one Enhanced Packet Block
    per ``(data, timestamp_ns)`` pair."""
    shb = _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    tsresol_opt = struct.pack("<HHB", 9, 1, 9) + b"\x00" * 3  # 10**-9 = ns
    end_opt = struct.pack("<HH", 0, 0)
    idb = _pcapng_block(
        1, struct.pack("<HHI", linktype, 0, 65_535) + tsresol_opt + end_opt
    )
    epbs = b"".join(
        _pcapng_block(
            6,
            struct.pack(
                "<IIIII",
                0,
                (timestamp_ns >> 32) & 0xFFFFFFFF,
                timestamp_ns & 0xFFFFFFFF,
                len(data),
                len(data),
            )
            + data,
        )
        for data, timestamp_ns in frames
    )
    return shb + idb + epbs


def _build_pcapng_simple_packet(data: bytes, *, linktype: int = 1) -> bytes:
    """A minimal pcapng capture carrying one Simple Packet Block, which
    (unlike an Enhanced Packet Block) has no timestamp field at all."""
    shb = _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = _pcapng_block(1, struct.pack("<HHI", linktype, 0, 65_535))
    spb = _pcapng_block(3, struct.pack("<I", len(data)) + data)
    return shb + idb + spb


class TestWriterFormat:
    def test_global_header_golden_bytes(self, tmp_path):
        path = tmp_path / "empty.pcap"
        PcapWriter(path).close()
        assert path.read_bytes() == struct.pack(
            "<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65_550, 1
        )

    def test_record_headers_carry_exact_nanoseconds(self, tmp_path):
        path = tmp_path / "two.pcap"
        with PcapWriter(path) as writer:
            for frame, timestamp in zip(FRAMES, TIMESTAMPS, strict=True):
                writer.write(frame, timestamp)
        data = path.read_bytes()
        cursor = 24
        seen = []
        for frame in FRAMES:
            ts_sec, ts_nsec, incl_len, orig_len = struct.unpack_from(
                "<IIII", data, cursor
            )
            assert incl_len == orig_len == len(frame)
            seen.append((ts_sec, ts_nsec))
            cursor += 16 + incl_len
        assert seen[0] == (1_787_000_000, 123_456_789)
        assert seen[1] == (1_787_000_000, 999_999_999)

    def test_exact_nanosecond_at_a_second_boundary(self, tmp_path):
        """Integer arithmetic (divmod), not float rounding, drives the
        split -- there is no carry edge case left to get wrong at a
        second boundary."""
        path = tmp_path / "boundary.pcap"
        with PcapWriter(path) as writer:
            writer.write(b"x" * 14, 1_787_000_001_000_000_000)
        ts_sec, ts_nsec = struct.unpack_from("<II", path.read_bytes(), 24)
        assert (ts_sec, ts_nsec) == (1_787_000_001, 0)


class TestReader:
    def test_write_read_round_trip(self, tmp_path):
        path = tmp_path / "roundtrip.pcap"
        with PcapWriter(path) as writer:
            for frame, timestamp in zip(FRAMES, TIMESTAMPS, strict=True):
                writer.write(frame, timestamp)
        replayed = list(read_captures(path))
        assert [frame for frame, _ in replayed] == FRAMES

    def test_big_endian_and_nanosecond_magic(self, tmp_path):
        for magic, frac, name in (
            (
                0xA1B2C3D4,
                500_000,
                "be-us",
            ),  # microsecond precision: half a second
            (
                0xA1B23C4D,
                500_000_000,
                "be-ns",
            ),  # nanosecond precision: half a second
        ):
            path = tmp_path / f"{name}.pcap"
            frame = FRAMES[0]
            path.write_bytes(
                struct.pack(">IHHiIII", magic, 2, 4, 0, 0, 65_550, 1)
                + struct.pack(
                    ">IIII",
                    1_787_000_000,
                    frac,
                    len(frame),
                    len(frame),
                )
                + frame
            )
            ((replayed, timestamp),) = list(read_captures(path))
            assert replayed == frame
            # Both encodings of "half a second past" convert to the same
            # exact integer nanosecond value -- proving the µs->ns and
            # ns->ns read paths are both exact, not just close.
            assert timestamp == 1_787_000_000_500_000_000

    def test_non_ethernet_linktype_rejected(self, tmp_path):
        path = tmp_path / "raw-ip.pcap"
        path.write_bytes(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_550, 101)
        )
        with pytest.raises(ValueError, match="linktype 101"):
            list(read_captures(path))

    def test_not_a_pcap_rejected(self, tmp_path):
        path = tmp_path / "not.pcap"
        path.write_bytes(b"PK\x03\x04 definitely a zip" + b"\x00" * 16)
        with pytest.raises(ValueError, match="unrecognized capture format"):
            list(read_captures(path))

    def test_truncated_record_diagnosed(self, tmp_path):
        path = tmp_path / "cut.pcap"
        with PcapWriter(path) as writer:
            writer.write(FRAMES[0], TIMESTAMPS[0])
        path.write_bytes(path.read_bytes()[:-4])
        with pytest.raises(ValueError, match="truncated"):
            list(read_captures(path))


class TestPcapngReader:
    """pcapng is read via netprotocols.read_captures (RootWire's own
    reader/writer never carried its own pcapng implementation) — these
    exercise auto-detection, exact nanosecond timestamps, and the same
    linktype gate the classic-pcap tests above cover."""

    def test_pcapng_round_trip(self, tmp_path):
        path = tmp_path / "capture.pcapng"
        frames = list(zip(FRAMES, TIMESTAMPS, strict=True))
        path.write_bytes(_build_pcapng(frames))
        replayed = list(read_captures(path))
        assert [frame for frame, _ in replayed] == FRAMES
        assert [ts for _, ts in replayed] == TIMESTAMPS

    def test_pcapng_non_ethernet_linktype_rejected(self, tmp_path):
        path = tmp_path / "raw-ip.pcapng"
        path.write_bytes(
            _build_pcapng([(FRAMES[0], TIMESTAMPS[0])], linktype=101)
        )
        with pytest.raises(ValueError, match="linktype 101"):
            list(read_captures(path))

    def test_pcapng_simple_packet_block_timestamp_is_zero(self, tmp_path):
        """A Simple Packet Block has no timestamp field at all (RFC
        draft §4.4) -- netprotocols reports 0 rather than guessing, and
        that must survive unchanged through RootWire's own reader."""
        path = tmp_path / "spb.pcapng"
        path.write_bytes(_build_pcapng_simple_packet(FRAMES[0]))
        ((frame, timestamp),) = list(read_captures(path))
        assert frame == FRAMES[0]
        assert timestamp == 0

    def test_replay_pcapng_through_cli(self, tmp_path, capsys):
        """The whole -r pipeline, not just the reader function."""
        path = tmp_path / "capture.pcapng"
        frames = list(zip(FRAMES, TIMESTAMPS, strict=True))
        path.write_bytes(_build_pcapng(frames))
        assert cli.main(["-r", str(path)]) == 0
        captured = capsys.readouterr()
        assert captured.out.count("Frame #") == len(FRAMES)


class TestCorpusReplay:
    def test_every_corpus_pcap_replays_through_the_pipeline(self):
        """read_captures must agree with the independent test reader and
        feed the decoder cleanly — the corpus doubles as the replay
        golden set."""
        expected = {}
        for name, _, frame in corpus_frames():
            expected.setdefault(name, []).append(frame)
        for pcap in sorted(FIXTURES.glob("*.pcap")):
            replayed = list(read_captures(pcap))
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
        ((replayed, _),) = list(read_captures(path))
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
        assert [f for f, _ in read_captures(copy)] == [
            f for f, _ in read_captures(source)
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
