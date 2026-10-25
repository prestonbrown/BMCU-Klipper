# SPDX-License-Identifier: GPL-3.0-or-later

import struct

import pytest

from bmcu_core import protocol


@pytest.mark.parametrize('data', [
    b'',
    b'\x00',
    b'\x00\x00',
    b'\x11\x00\x22',
    bytes(range(1, 255)),
    bytes(range(1, 256)) * 3,
    b'\x00' + bytes(range(1, 255)) + b'\x00',
])
def test_cobs_round_trip(data):
    encoded = protocol.cobs_encode(data)
    assert b'\x00' not in encoded
    assert protocol.cobs_decode(encoded) == data


def test_cobs_decode_rejects_embedded_zero():
    with pytest.raises(ValueError):
        protocol.cobs_decode(b'\x03\x01\x00\x02')


def test_cobs_decode_rejects_truncated_block():
    with pytest.raises(ValueError):
        protocol.cobs_decode(b'\x05\x01\x02')


def test_packet_round_trip():
    frame = protocol.encode_packet(protocol.MSG_PING, 7, 42, b'\x00B\x00')
    assert frame[:1] == b'\x00' and frame[-1:] == b'\x00'
    assert b'\x00' not in frame[1:-1]
    decoded = protocol.cobs_decode(frame[1:-1])
    assert protocol.decode_packet(decoded) == (protocol.MSG_PING, 7, 42, b'\x00B\x00')


def _decoded(msg_type=protocol.MSG_PING, seq=1, cmd_id=1, payload=b'x'):
    return bytearray(protocol.cobs_decode(
        protocol.encode_packet(msg_type, seq, cmd_id, payload)[1:-1]))


def test_decode_rejects_crc_mismatch():
    body = _decoded()
    body[-1] ^= 0x01
    with pytest.raises(ValueError, match='CRC'):
        protocol.decode_packet(bytes(body))


def test_decode_rejects_payload_length_mismatch():
    body = _decoded(payload=b'abc')
    struct.pack_into('<H', body, 2, 2)
    body[-4:] = struct.pack('<I', protocol.crc32(bytes(body[:-4])))
    with pytest.raises(ValueError, match='length'):
        protocol.decode_packet(bytes(body))


def test_decode_rejects_other_protocol_version():
    body = _decoded()
    body[0] = protocol.PROTO_VERSION + 1
    body[-4:] = struct.pack('<I', protocol.crc32(bytes(body[:-4])))
    with pytest.raises(protocol.ProtocolVersionError):
        protocol.decode_packet(bytes(body))


def test_stream_decoder_reassembles_split_frames():
    frames = (protocol.encode_packet(protocol.MSG_PONG, 1, 10, b'a') +
              protocol.encode_packet(protocol.MSG_PONG, 2, 11, b'bb'))
    decoder = protocol.StreamDecoder()
    packets = []
    for byte in frames:
        packets.extend(decoder.feed(bytes([byte])))
    assert [(p[1], p[2], p[3]) for p in packets] == [(1, 10, b'a'), (2, 11, b'bb')]
    assert decoder.errors == 0


def test_stream_decoder_drops_corrupt_frame_and_keeps_the_next():
    good = protocol.encode_packet(protocol.MSG_PONG, 2, 11, b'ok')
    bad = bytearray(protocol.encode_packet(protocol.MSG_PONG, 1, 10, b'xx'))
    bad[3] ^= 0x40
    decoder = protocol.StreamDecoder()
    packets = decoder.feed(bytes(bad) + good)
    assert [(p[1], p[2], p[3]) for p in packets] == [(2, 11, b'ok')]
    assert decoder.errors == 1


def test_stream_decoder_discards_oversized_frame_until_delimiter():
    decoder = protocol.StreamDecoder(max_frame=32)
    good = protocol.encode_packet(protocol.MSG_PONG, 3, 12, b'')
    packets = decoder.feed(b'\x00' + b'\x01' * 40 + good)
    assert [(p[1], p[2]) for p in packets] == [(3, 12)]
    assert decoder.errors == 1


def test_stream_decoder_records_incompatible_version():
    body = _decoded()
    body[0] = protocol.PROTO_VERSION + 1
    body[-4:] = struct.pack('<I', protocol.crc32(bytes(body[:-4])))
    decoder = protocol.StreamDecoder()
    assert decoder.feed(b'\x00' + protocol.cobs_encode(bytes(body)) + b'\x00') == []
    assert decoder.incompatible_version == protocol.PROTO_VERSION + 1


def test_stream_decoder_pending_tracks_unterminated_frame():
    decoder = protocol.StreamDecoder()
    assert not decoder.pending
    frame = protocol.encode_packet(protocol.MSG_PING, 1, 2, b'x')
    assert decoder.feed(frame[:5]) == []
    assert decoder.pending
    assert decoder.feed(frame[5:]) == [(protocol.MSG_PING, 1, 2, b'x')]
    assert not decoder.pending
    decoder.feed(b'\x00' + b'\x01' * 300)
    assert decoder.pending
    decoder.feed(b'\x00')
    assert not decoder.pending
