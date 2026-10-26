# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import errno
import logging
import os
import random
import socket
import struct
import threading
import time

import pytest

import bmcu_transportd
from bmcu_core import protocol, transport

from bmcu_sim import BmcuSim


class Client(object):
    """A Klipper-side IPC client of the daemon's unix socket."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.sock.setblocking(False)
        self.decoder = transport.MessageDecoder()
        self.messages = []

    def close(self):
        self.sock.close()

    def send(self, msg_type, cmd_id, payload=b''):
        self.sock.sendall(transport.encode_message(
            transport.OP_SEND, msg_type, cmd_id, 0, payload))

    def poll(self):
        while True:
            try:
                data = self.sock.recv(65536)
            except BlockingIOError:
                return
            if not data:
                return
            self.messages.extend(self.decoder.feed(data))

    def packets(self, msg_type=None, cmd_id=None):
        self.poll()
        return [m for m in self.messages
                if m[0] == transport.OP_PACKET and
                (msg_type is None or m[1] == msg_type) and
                (cmd_id is None or m[3] == cmd_id)]

    def links(self):
        self.poll()
        return [m for m in self.messages if m[0] == transport.OP_LINK]


def wait_until(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.005)
    return predicate()


class Harness(object):
    def __init__(self, tmp_path, sim, rng=None, **overrides):
        self.sim = sim
        lock = open(str(tmp_path / 'transport.lock'), 'w+')
        options = dict(
            name='bmcu_test', port=sim.port, expected_uid='',
            scan_fallback=False, exclude_ports=(),
            socket=str(tmp_path / 'bmcu.sock'), baud=115200,
            heartbeat=5.0, connection_timeout=15.0, reconnect=0.1,
            status_interval=0.5, connect_settle=0.0,
            status_file=str(tmp_path / 'status.json'),
            settings_digest='', lifetime_lock=lock, process_record={},
            half_duplex=False, resend_timeout=0.25, resend_attempts=3,
            rx_quiet_ms=2.0)
        options.update(overrides)
        self.args = argparse.Namespace(**options)
        self.daemon = bmcu_transportd.TransportDaemon(
            self.args, rng if rng is not None else random.Random(1))
        self.error = None
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.clients = []
        # setup() marks the process record ready once both sockets listen.
        assert wait_until(lambda: self.args.process_record.get('ready'))

    def _run(self):
        try:
            self.daemon.run()
        except BaseException as exc:
            self.error = exc

    def connect(self):
        client = Client(self.args.socket)
        self.clients.append(client)
        return client

    def wait_ready(self, timeout=2.0):
        assert wait_until(lambda: self.daemon.session_ready, timeout), \
            'handshake did not complete'
        # The snapshot and update-cancel requests that follow readiness.
        assert wait_until(lambda: self.daemon.latest_snapshot is not None and
                          not self.daemon.internal_pending, timeout)

    def stop(self):
        for client in self.clients:
            client.close()
        self.daemon.running = False
        self.thread.join(2.0)
        self.args.lifetime_lock.close()
        assert not self.thread.is_alive()
        assert self.error is None, repr(self.error)


@pytest.fixture
def sim():
    value = BmcuSim()
    yield value
    value.close()


@pytest.fixture
def start(tmp_path, sim):
    harnesses = []

    def factory(**overrides):
        harness = Harness(tmp_path, sim, **overrides)
        harnesses.append(harness)
        return harness

    yield factory
    for harness in harnesses:
        harness.stop()


def test_handshake_completes_and_reports_ready(start, sim):
    h = start()
    client = h.connect()
    h.wait_ready()
    hello = sim.frames('rx', protocol.MSG_HELLO)
    confirm = sim.frames('rx', protocol.MSG_SESSION_CONFIRM)
    assert len(hello) == 1 and len(confirm) == 1
    assert struct.unpack('<I', confirm[0].payload)[0] == sim.session_id
    assert h.daemon.session_id == sim.session_id
    assert h.daemon.runtime_uid == sim.uid.hex().upper()
    # Readiness is followed by leaving update mode and a snapshot request.
    after = [f.msg_type for f in sim.frames('rx') if f.time > confirm[0].time]
    assert after[:2] == [protocol.MSG_UPDATE_CANCEL, protocol.MSG_GET_SNAPSHOT]
    assert wait_until(lambda: any(m[1] == 1 for m in client.links()))
    online = [m for m in client.links() if m[1] == 1][-1]
    assert online[3] == sim.session_id


def test_wire_seq_starts_at_one_and_increases(start, sim):
    h = start()
    h.wait_ready()
    seqs = [f.seq for f in sim.frames('rx')]
    assert seqs == list(range(1, len(seqs) + 1))
    assert sim.duplicates == 0


def test_dropped_hello_ack_retries_then_times_out(start, sim):
    sim.add_fault('drop', protocol.MSG_HELLO, count=-1)
    h = start(connection_timeout=1.0, reconnect=5.0)
    client = h.connect()
    assert wait_until(lambda: len(sim.frames('rx', protocol.MSG_HELLO)) >= 2, 1.5)
    hellos = sim.frames('rx', protocol.MSG_HELLO)
    assert 0.5 <= hellos[1].time - hellos[0].time <= 0.95
    assert not h.daemon.session_ready
    assert wait_until(lambda: h.daemon.serial is None, 1.5)
    assert not h.daemon.session_ready
    assert wait_until(lambda: any(
        m[1] == 0 and m[4] == b'HELLO/session handshake timeout'
        for m in client.links()))


def test_hello_ack_with_invalid_uid_is_rejected(tmp_path):
    bad = BmcuSim(uid=b'\x00' * 12)
    try:
        h = Harness(tmp_path, bad, reconnect=0.1)
        try:
            assert wait_until(lambda: h.daemon.serial_generation >= 2, 1.5)
            assert not h.daemon.session_ready
            assert not bad.frames('rx', protocol.MSG_SESSION_CONFIRM)
        finally:
            h.stop()
    finally:
        bad.close()


def test_hello_ack_from_unexpected_uid_is_rejected(start, sim):
    h = start(expected_uid='AB' * 12)
    assert wait_until(lambda: sim.frames('rx', protocol.MSG_HELLO))
    assert wait_until(lambda: h.daemon.serial is None and
                      h.daemon.foreign_uid_until, 1.0)
    time.sleep(0.3)
    assert not h.daemon.session_ready
    assert not sim.frames('rx', protocol.MSG_SESSION_CONFIRM)


def test_rejected_session_confirm_does_not_go_ready(start, sim):
    sim.add_fault('ignore', protocol.MSG_SESSION_CONFIRM, count=-1)
    h = start(connection_timeout=0.8, reconnect=5.0)
    client = h.connect()
    assert wait_until(lambda: sim.frames('rx', protocol.MSG_SESSION_CONFIRM))
    assert wait_until(lambda: h.daemon.serial is None, 1.5)
    assert not h.daemon.session_ready
    assert wait_until(lambda: [m for m in client.links() if m[1] == 0 and m[4]])
    assert not [m for m in client.links() if m[1] == 1]


def test_client_request_round_trips_with_client_cmd_id(start, sim):
    h = start()
    client = h.connect()
    h.wait_ready()
    client.send(protocol.MSG_PING, 77, b'xyz')
    reply = wait_until(lambda: client.packets(protocol.MSG_PONG, 77))
    assert reply and reply[0][4] == b'xyz'
    wire = sim.frames('rx', protocol.MSG_PING)
    assert len(wire) == 1 and wire[0].payload == b'xyz'
    # The wire carries the daemon's own command id, not the client's.
    assert wire[0].cmd_id != 77
    assert wire[0].cmd_id not in h.daemon.external_pending


def test_ack_payload_echo_is_rewritten_to_client_cmd_id(start, sim):
    h = start()
    client = h.connect()
    h.wait_ready()
    client.send(protocol.MSG_SET_ACTIVE_CH, 4242, b'\x02')
    ack = wait_until(lambda: client.packets(protocol.MSG_ACK, 4242))
    assert ack
    assert struct.unpack('<IBH', ack[0][4]) == (4242, 1, 0)
    wire = sim.frames('rx', protocol.MSG_SET_ACTIVE_CH)[0]
    assert sim.frames('tx', protocol.MSG_ACK)[-1].payload[:4] == \
        struct.pack('<I', wire.cmd_id)


def test_client_get_status_reply_is_routed_to_requester(start, sim):
    h = start()
    client = h.connect()
    h.wait_ready()
    client.send(protocol.MSG_GET_STATUS, 31)
    reply = wait_until(lambda: client.packets(protocol.MSG_STATUS, 31))
    assert reply
    assert protocol.parse_status(reply[0][4])['session_id'] == sim.session_id


def test_request_while_offline_is_refused(start, sim):
    sim.add_fault('drop', protocol.MSG_HELLO, count=-1)
    h = start()
    client = h.connect()
    assert wait_until(lambda: sim.frames('rx', protocol.MSG_HELLO))
    client.send(protocol.MSG_PING, 9, b'a')
    error = wait_until(lambda: client.poll() or [
        m for m in client.messages if m[0] == transport.OP_ERROR and m[1] == 9])
    assert error and error[0][4] == b'BMCU transport is offline'
    assert not sim.frames('rx', protocol.MSG_PING)


def test_corrupted_reply_is_discarded_and_link_survives(start, sim):
    h = start()
    client = h.connect()
    h.wait_ready()
    generation = h.daemon.serial_generation
    sim.add_fault('corrupt', protocol.MSG_PING)
    client.send(protocol.MSG_PING, 5, b'first')
    assert wait_until(lambda: [f for f in sim.frames('tx', protocol.MSG_PONG)
                               if f.note == 'corrupt'])
    assert wait_until(lambda: h.daemon.serial_decoder.errors >= 1)
    client.send(protocol.MSG_PING, 6, b'second')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 6))
    assert not client.packets(protocol.MSG_PONG, 5)
    assert h.daemon.session_ready
    assert h.daemon.serial_generation == generation


def test_line_noise_between_frames_is_tolerated(start, sim):
    h = start()
    client = h.connect()
    h.wait_ready()
    sim.send_raw(b'\x00\x17\x99\x42garbage\x00\xff\xfe')
    client.send(protocol.MSG_PING, 12, b'ok')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 12))
    assert h.daemon.session_ready


def test_unsolicited_status_change_is_relayed(start, sim):
    h = start(status_interval=60.0)
    client = h.connect()
    h.wait_ready()
    sim.set_present(2, True)
    assert wait_until(lambda: [
        m for m in client.packets(protocol.MSG_STATUS, 0)
        if protocol.parse_status(m[4])['present'][2] == 1])
    # A second change inside status_interval is relayed because it changed.
    sim.set_present(3, True)
    assert wait_until(lambda: [
        m for m in client.packets(protocol.MSG_STATUS, 0)
        if protocol.parse_status(m[4])['present'][3] == 1])
    assert h.daemon.latest_status_dict['present'] == [0, 0, 1, 1]


def test_unchanged_status_is_rate_limited(start, sim):
    h = start(status_interval=60.0)
    client = h.connect()
    h.wait_ready()
    sim.set_present(2, True)
    assert wait_until(lambda: client.packets(protocol.MSG_STATUS, 0))
    before = len(client.packets(protocol.MSG_STATUS, 0))
    for _ in range(3):
        sim.send_status()
    assert wait_until(lambda: len(sim.frames('tx', protocol.MSG_STATUS)) >= 4)
    client.send(protocol.MSG_PING, 60, b'sync')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 60))
    assert len(client.packets(protocol.MSG_STATUS, 0)) == before


def test_status_interleaved_before_reply_reaches_both(start, sim):
    h = start()
    client = h.connect()
    h.wait_ready()
    sim.present[1] = 1
    sim.add_fault('status_before', protocol.MSG_PING)
    client.send(protocol.MSG_PING, 40, b'p')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 40))
    statuses = client.packets(protocol.MSG_STATUS, 0)
    assert any(protocol.parse_status(m[4])['present'][1] == 1 for m in statuses)
    sent = [f.msg_type for f in sim.frames('tx')][-2:]
    assert sent == [protocol.MSG_STATUS, protocol.MSG_PONG]


def test_delayed_reply_is_still_delivered(start, sim):
    h = start()
    client = h.connect()
    h.wait_ready()
    sim.add_fault('delay', protocol.MSG_PING, seconds=0.3)
    client.send(protocol.MSG_PING, 50, b'late')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 50), 1.5)
    request = sim.frames('rx', protocol.MSG_PING)[-1]
    reply = sim.frames('tx', protocol.MSG_PONG)[-1]
    assert reply.time - request.time >= 0.3
    assert h.daemon.session_ready


def test_heartbeat_ping_after_idle_interval(start, sim):
    h = start(heartbeat=0.3, connection_timeout=5.0)
    h.wait_ready()
    assert wait_until(lambda: len(sim.frames('rx', protocol.MSG_PING)) >= 2, 2.0)
    frames = sim.frames('rx')
    pings = [i for i, f in enumerate(frames) if f.msg_type == protocol.MSG_PING]
    first = frames[pings[0]]
    assert first.payload == b'B'
    idle = first.time - frames[pings[0] - 1].time
    assert 0.3 <= idle <= 0.9
    # A PONG clears the outstanding heartbeat, so the next one follows after
    # one more idle interval instead of waiting out the retry period (1 s).
    gap = frames[pings[1]].time - first.time
    assert 0.3 <= gap <= 0.95
    assert h.daemon.session_ready


def test_silent_device_closes_link_after_receive_timeout(start, sim):
    h = start(heartbeat=0.3, connection_timeout=1.0, reconnect=5.0)
    client = h.connect()
    h.wait_ready()
    sim.silent = True
    silenced = time.monotonic()
    assert wait_until(lambda: h.daemon.serial is None, 2.0)
    elapsed = time.monotonic() - silenced
    assert 0.7 <= elapsed <= 1.6
    assert sim.frames('rx', protocol.MSG_PING)
    assert wait_until(lambda: any(
        m[1] == 0 and m[4] == b'receive timeout after heartbeat retries'
        for m in client.links()))


def test_sim_drops_stale_seq_like_firmware():
    sim = BmcuSim()
    try:
        sim.handle_packet(protocol.MSG_HELLO, 1, 1, b'\0\0\0\0')
        sim.handle_packet(protocol.MSG_SESSION_CONFIRM, 2, 2,
                          struct.pack('<I', sim.session_id))
        sim.handle_packet(protocol.MSG_PING, 3, 3, b'a')
        sim.handle_packet(protocol.MSG_PING, 3, 4, b'b')
        sim.handle_packet(protocol.MSG_PING, 2, 5, b'c')
        sim.handle_packet(protocol.MSG_PING, 4, 6, b'd')
        assert sim.wait_for(lambda: len(sim.frames('tx', protocol.MSG_PONG)) >= 2)
        pongs = sim.frames('tx', protocol.MSG_PONG)
        assert [f.cmd_id for f in pongs] == [3, 6]
        assert sim.duplicates == 2
    finally:
        sim.close()


FEED = struct.pack('<BfBI', 1, 100.0, 0, 5000)


def start_half_duplex(start, **overrides):
    options = dict(half_duplex=True, resend_timeout=0.1, resend_attempts=3)
    options.update(overrides)
    return start(**options)


def test_parse_args_half_duplex_defaults(monkeypatch):
    base = ['bmcu_transportd', '--name', 'n', '--port', '/dev/null',
            '--socket', '/tmp/s', '--log-file', '/tmp/l', '--status-file', '/tmp/f']
    monkeypatch.setattr('sys.argv', base)
    args = bmcu_transportd.parse_args()
    assert (args.half_duplex, args.resend_timeout, args.resend_attempts) == (False, 0.25, 3)
    monkeypatch.setattr('sys.argv', base + ['--half-duplex', '--resend-timeout', '0.5',
                                            '--resend-attempts', '5'])
    args = bmcu_transportd.parse_args()
    assert (args.half_duplex, args.resend_timeout, args.resend_attempts) == (True, 0.5, 5)


def test_half_duplex_lost_request_is_resent_with_same_cmd_and_new_seq(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_PING)
    client.send(protocol.MSG_PING, 70, b'r')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 70))
    wire = sim.frames('rx', protocol.MSG_PING)
    assert len(wire) == 2
    assert wire[0].cmd_id == wire[1].cmd_id
    assert wire[1].seq > wire[0].seq
    assert wire[1].time - wire[0].time >= 0.07
    assert wire[1].payload == b'r'
    assert len(client.packets(protocol.MSG_PONG, 70)) == 1


def test_half_duplex_lost_operation_ack_does_not_start_a_second_operation(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('drop', protocol.MSG_FEED_DISTANCE)
    client.send(protocol.MSG_FEED_DISTANCE, 300, FEED)
    ack = wait_until(lambda: client.packets(protocol.MSG_ACK, 300))
    assert ack and struct.unpack('<IBH', ack[0][4]) == (300, 1, 0)
    wire = sim.frames('rx', protocol.MSG_FEED_DISTANCE)
    assert len(wire) == 2 and wire[0].cmd_id == wire[1].cmd_id
    assert sim.operations_started == [wire[0].cmd_id]
    # The ACK ends resending while the operation is still running.
    time.sleep(0.3)
    assert len(sim.frames('rx', protocol.MSG_FEED_DISTANCE)) == 2
    sim.complete_operation(wire[0].cmd_id)
    result = wait_until(lambda: client.packets(protocol.MSG_OP_RESULT, 300))
    assert result and protocol.parse_op_result(result[0][4])['op_id'] == 300
    assert len(client.packets(protocol.MSG_ACK, 300)) == 1


def test_half_duplex_late_operation_ack_reaches_client_once(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('delay', protocol.MSG_FEED_DISTANCE, seconds=0.2)
    client.send(protocol.MSG_FEED_DISTANCE, 301, FEED)
    assert wait_until(lambda: client.packets(protocol.MSG_ACK, 301))
    # Both the replayed and the delayed original ACK reach the daemon.
    assert wait_until(lambda: len(sim.frames('tx', protocol.MSG_ACK)) >= 4)
    client.send(protocol.MSG_PING, 302, b'sync')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 302))
    assert len(sim.operations_started) == 1
    assert len(client.packets(protocol.MSG_ACK, 301)) == 1


def test_half_duplex_corrupted_reply_is_resent(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('corrupt', protocol.MSG_PING)
    client.send(protocol.MSG_PING, 71, b'c')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 71))
    assert len(sim.frames('rx', protocol.MSG_PING)) == 2
    assert h.daemon.serial_decoder.errors >= 1
    assert len(client.packets(protocol.MSG_PONG, 71)) == 1


def test_half_duplex_resend_stops_at_max_attempts(start, sim):
    h = start_half_duplex(start, resend_attempts=3)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_PING, count=-1)
    client.send(protocol.MSG_PING, 72, b'x')
    assert wait_until(lambda: len(sim.frames('rx', protocol.MSG_PING)) >= 3, 1.0)
    time.sleep(0.35)
    wire = sim.frames('rx', protocol.MSG_PING)
    assert len(wire) == 3
    assert len({f.cmd_id for f in wire}) == 1
    assert [f.seq for f in wire] == sorted({f.seq for f in wire})
    assert all(b.time - a.time >= 0.07 for a, b in zip(wire, wire[1:]))
    assert not client.packets(protocol.MSG_PONG, 72)
    # The request keeps the ordinary external timeout bookkeeping.
    assert wire[0].cmd_id in h.daemon.external_pending
    assert not h.daemon.resend
    assert h.daemon.session_ready


def test_half_duplex_no_resend_once_a_reply_arrived(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('status_before', protocol.MSG_PING)
    client.send(protocol.MSG_PING, 73, b's')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 73))
    time.sleep(0.3)
    assert len(sim.frames('rx', protocol.MSG_PING)) == 1
    assert not h.daemon.resend


def test_half_duplex_error_reply_also_stops_resend(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    client.send(protocol.MSG_SET_ACTIVE_CH, 74, b'\x07')
    assert wait_until(lambda: client.packets(protocol.MSG_ERROR, 74))
    time.sleep(0.3)
    assert len(sim.frames('rx', protocol.MSG_SET_ACTIVE_CH)) == 1


def test_full_duplex_never_resends(start, sim):
    h = start(resend_timeout=0.1)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_PING)
    client.send(protocol.MSG_PING, 75, b'n')
    time.sleep(0.45)
    assert len(sim.frames('rx', protocol.MSG_PING)) == 1
    assert not client.packets(protocol.MSG_PONG, 75)
    assert not h.daemon.resend


def test_half_duplex_channel_preload_is_never_resent(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_CHANNEL_PRELOAD)
    client.send(protocol.MSG_CHANNEL_PRELOAD, 76, b'\x01')
    time.sleep(0.35)
    assert len(sim.frames('rx', protocol.MSG_CHANNEL_PRELOAD)) == 1


def test_half_duplex_stops_resending_when_client_leaves(start, sim):
    h = start_half_duplex(start, resend_attempts=50)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_PING, count=-1)
    client.send(protocol.MSG_PING, 77, b'g')
    assert wait_until(lambda: len(sim.frames('rx', protocol.MSG_PING)) >= 2)
    client.close()
    h.clients.remove(client)
    assert wait_until(lambda: not h.daemon.external_pending)
    time.sleep(0.05)
    sent = len(sim.frames('rx', protocol.MSG_PING))
    time.sleep(0.3)
    assert len(sim.frames('rx', protocol.MSG_PING)) == sent


def test_half_duplex_orphaned_operation_is_not_resent(start, sim):
    h = start_half_duplex(start, resend_attempts=50)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_FEED_DISTANCE, count=-1)
    client.send(protocol.MSG_FEED_DISTANCE, 310, FEED)
    assert wait_until(lambda: len(sim.frames('rx', protocol.MSG_FEED_DISTANCE)) >= 2)
    client.close()
    h.clients.remove(client)
    assert wait_until(lambda: sim.frames('rx', protocol.MSG_ABORT_OP))
    time.sleep(0.05)
    sent = len(sim.frames('rx', protocol.MSG_FEED_DISTANCE))
    time.sleep(0.3)
    assert len(sim.frames('rx', protocol.MSG_FEED_DISTANCE)) == sent


@pytest.mark.parametrize('action', ['ignore', 'drop'])
def test_half_duplex_lost_session_confirm_is_resent(tmp_path, sim, start, action):
    sim.add_fault(action, protocol.MSG_SESSION_CONFIRM)
    began = time.monotonic()
    h = start_half_duplex(start)
    h.wait_ready()
    # Ready on the first session: without the resend the handshake restarts
    # with a second HELLO after 1 s.
    assert time.monotonic() - began < 3.0
    assert len(sim.frames('rx', protocol.MSG_HELLO)) == 1
    confirms = sim.frames('rx', protocol.MSG_SESSION_CONFIRM)
    assert len(confirms) == 2
    assert confirms[0].cmd_id == confirms[1].cmd_id
    assert confirms[1].seq > confirms[0].seq


@pytest.mark.parametrize('msg_type', [protocol.MSG_UPDATE_CANCEL,
                                      protocol.MSG_GET_SNAPSHOT])
def test_half_duplex_lost_startup_request_is_resent(start, sim, msg_type):
    sim.add_fault('ignore', msg_type)
    h = start_half_duplex(start)
    h.wait_ready()
    wire = sim.frames('rx', msg_type)
    assert len(wire) == 2 and wire[0].cmd_id == wire[1].cmd_id


def test_half_duplex_write_waits_for_partial_frame(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    frame = protocol.encode_packet(protocol.MSG_STATUS, 999, 0, sim.status_payload())
    head, tail = frame[:20], frame[20:]
    sim.send_raw(head)
    assert wait_until(lambda: h.daemon.serial_decoder.pending)
    client.send(protocol.MSG_PING, 80, b'g')
    time.sleep(0.02)
    sim.send_raw(tail)
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 80))
    tail_sent = [f for f in sim.frames('tx') if f.raw == tail][0]
    assert sim.frames('rx', protocol.MSG_PING)[-1].time >= tail_sent.time


def test_half_duplex_write_gate_releases_after_bound(start, sim):
    # A long resend timeout keeps the resend timer from waking the loop.
    h = start_half_duplex(start, resend_timeout=1.0)
    client = h.connect()
    h.wait_ready()
    sim.send_raw(b'\x00\x05\x01\x02')
    assert wait_until(lambda: h.daemon.serial_decoder.pending)
    noise = [f for f in sim.frames('tx') if f.raw == b'\x00\x05\x01\x02'][0]
    client.send(protocol.MSG_PING, 81, b'b')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 81), 1.0)
    held = sim.frames('rx', protocol.MSG_PING)[-1].time - noise.time
    assert 0.05 <= held < 0.2


def test_partial_frame_age_restarts_with_each_new_frame(start, sim):
    h = start_half_duplex(start)
    h.wait_ready()
    first = protocol.encode_packet(protocol.MSG_STATUS, 900, 0, sim.status_payload())
    second = protocol.encode_packet(protocol.MSG_STATUS, 901, 0, sim.status_payload())
    sim.send_raw(first[:20])
    assert wait_until(lambda: h.daemon.serial_decoder.pending)
    between = time.monotonic()
    statuses = h.daemon.latest_status
    # The rest of one frame and the start of the next arrive in one read.
    sim.send_raw(first[20:] + second[:20])
    assert wait_until(lambda: h.daemon.latest_status is not statuses and
                      h.daemon.serial_decoder.pending)
    assert h.daemon.partial_since >= between


def test_full_duplex_write_ignores_partial_frame(start, sim, monkeypatch):
    # A long bound makes a wrongly applied gate obvious on a loaded machine.
    monkeypatch.setattr(bmcu_transportd, '_WRITE_GATE_MAX', 2.0)
    h = start()
    client = h.connect()
    h.wait_ready()
    sim.send_raw(b'\x00\x05\x01\x02')
    assert wait_until(lambda: h.daemon.serial_decoder.pending)
    sent = time.monotonic()
    client.send(protocol.MSG_PING, 82, b'f')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 82))
    assert sim.frames('rx', protocol.MSG_PING)[-1].time - sent < 1.0


def test_sim_replays_operations_and_rejects_repeated_preload():
    sim = BmcuSim()
    try:
        sim.handle_packet(protocol.MSG_HELLO, 1, 1, b'\0\0\0\0')
        sim.handle_packet(protocol.MSG_SESSION_CONFIRM, 2, 2,
                          struct.pack('<I', sim.session_id))
        sim.handle_packet(protocol.MSG_FEED_DISTANCE, 3, 50, FEED)
        sim.handle_packet(protocol.MSG_FEED_DISTANCE, 4, 50, FEED)
        assert sim.operations_started == [50]
        sim.handle_packet(protocol.MSG_CHANNEL_PRELOAD, 5, 60, b'\x02')
        sim.handle_packet(protocol.MSG_CHANNEL_PRELOAD, 6, 60, b'\x02')
        assert sim.wait_for(lambda: sim.frames('tx', protocol.MSG_ERROR))
        error = sim.frames('tx', protocol.MSG_ERROR)[0]
        assert error.cmd_id == 60 and struct.unpack('<BHI', error.payload)[1] == 40
        assert len([f for f in sim.frames('tx', protocol.MSG_ACK) if f.cmd_id == 50]) == 2
    finally:
        sim.close()


class FixedUniform(object):
    """An rng whose uniform() returns one end of the requested range."""

    def __init__(self, end):
        self.end = end
        self.calls = []

    def uniform(self, low, high):
        self.calls.append((low, high))
        return high if self.end == 'high' else low

    def randrange(self, start, stop):
        return start


@pytest.mark.parametrize('end,factor', [('low', 0.8), ('high', 1.2)])
def test_resend_wait_jitter_bounds(end, factor):
    args = argparse.Namespace(resend_timeout=0.25)
    rng = FixedUniform(end)
    daemon = bmcu_transportd.TransportDaemon(args, rng)
    assert daemon._resend_wait() == pytest.approx(0.25 * factor)
    assert rng.calls == [(0.8, 1.2)]


def test_resend_wait_varies_and_stays_in_bounds():
    args = argparse.Namespace(resend_timeout=0.25)
    daemon = bmcu_transportd.TransportDaemon(args, random.Random(7))
    waits = [daemon._resend_wait() for _ in range(200)]
    assert all(0.2 <= wait <= 0.3 for wait in waits)
    assert len(set(waits)) > 100


def test_half_duplex_resend_waits_use_jitter(tmp_path, sim):
    rng = FixedUniform('high')
    h = Harness(tmp_path, sim, rng=rng, half_duplex=True,
                resend_timeout=0.1, resend_attempts=3)
    try:
        client = h.connect()
        h.wait_ready()
        sim.add_fault('ignore', protocol.MSG_PING, count=-1)
        client.send(protocol.MSG_PING, 90, b'j')
        assert wait_until(lambda: len(sim.frames('rx', protocol.MSG_PING)) >= 3, 1.0)
        wire = sim.frames('rx', protocol.MSG_PING)
        # 1.2 x 0.1 s between sends; without the factor they come 0.1 s apart.
        assert all(b.time - a.time >= 0.115 for a, b in zip(wire, wire[1:]))
    finally:
        h.stop()


def low_latency_records(caplog):
    return [r for r in caplog.records if 'serial low-latency' in r.getMessage()]


def test_half_duplex_open_survives_unsupported_low_latency(start, sim, caplog):
    caplog.set_level(logging.INFO)
    h = start_half_duplex(start)
    h.wait_ready()
    records = low_latency_records(caplog)
    assert len(records) == 1
    assert records[0].getMessage().startswith('serial low-latency not supported: ')
    assert records[0].levelno == logging.INFO


def test_full_duplex_never_requests_low_latency(start, sim, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    calls = []
    monkeypatch.setattr(bmcu_transportd, '_serial_ioctl',
                        lambda *args: calls.append(args))
    h = start()
    h.wait_ready()
    assert calls == []
    assert low_latency_records(caplog) == []


def test_half_duplex_requests_low_latency_once_per_open(start, sim, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    calls = []

    def fake(fd, request, *rest):
        calls.append(request)
        raise OSError(errno.ENOTTY, 'Inappropriate ioctl for device')
    monkeypatch.setattr(bmcu_transportd, '_serial_ioctl', fake)
    h = start_half_duplex(start)
    h.wait_ready()
    assert calls == [bmcu_transportd._TIOCGSERIAL]
    assert [r.getMessage() for r in low_latency_records(caplog)] == [
        'serial low-latency not supported: Inappropriate ioctl for device']


class FakeSerialIoctl(object):
    def __init__(self, flags, fail_set=None):
        self.original = bytearray(range(1, bmcu_transportd._SERIAL_STRUCT.size + 1))
        struct.pack_into('@i', self.original, bmcu_transportd._SERIAL_FLAGS_OFFSET, flags)
        self.fail_set = fail_set
        self.written = None
        self.requests = []

    def __call__(self, fd, request, buffer, mutate=False):
        self.requests.append(request)
        if request == bmcu_transportd._TIOCGSERIAL:
            assert mutate is True and len(buffer) == len(self.original)
            buffer[:] = self.original
            return 0
        if self.fail_set is not None:
            raise OSError(self.fail_set, os.strerror(self.fail_set))
        self.written = bytes(buffer)
        return 0


def test_low_latency_sets_only_the_flag_bit(monkeypatch):
    fake = FakeSerialIoctl(0x10000040)
    monkeypatch.setattr(bmcu_transportd, '_serial_ioctl', fake)
    assert bmcu_transportd.request_low_latency(5) is None
    assert fake.requests == [bmcu_transportd._TIOCGSERIAL, bmcu_transportd._TIOCSSERIAL]
    expected = bytearray(fake.original)
    struct.pack_into('@i', expected, bmcu_transportd._SERIAL_FLAGS_OFFSET,
                     0x10000040 | 0x2000)
    assert fake.written == bytes(expected)
    assert len(fake.written) == struct.calcsize('@iiIiiiiiHcciHHPHIL')


def test_low_latency_already_set_writes_nothing(monkeypatch):
    fake = FakeSerialIoctl(0x2000)
    monkeypatch.setattr(bmcu_transportd, '_serial_ioctl', fake)
    assert bmcu_transportd.request_low_latency(5) is None
    assert fake.requests == [bmcu_transportd._TIOCGSERIAL]


def test_low_latency_set_refused_reports_reason(monkeypatch):
    fake = FakeSerialIoctl(0, fail_set=errno.EPERM)
    monkeypatch.setattr(bmcu_transportd, '_serial_ioctl', fake)
    assert bmcu_transportd.request_low_latency(5) == os.strerror(errno.EPERM)


def test_serial_struct_layout_matches_kernel():
    size = bmcu_transportd._SERIAL_STRUCT.size
    assert size == (72 if struct.calcsize('P') == 8 else 60)
    assert bmcu_transportd._SERIAL_FLAGS_OFFSET == 16


def test_half_duplex_logs_low_latency_on_with_latency_timer(start, sim, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    fake = FakeSerialIoctl(0)
    monkeypatch.setattr(bmcu_transportd, '_serial_ioctl', fake)
    ports = []
    monkeypatch.setattr(bmcu_transportd, '_usb_latency_timer',
                        lambda port: ports.append(port) or '1')
    h = start_half_duplex(start)
    h.wait_ready()
    assert ports == [sim.port]
    assert [r.getMessage() for r in low_latency_records(caplog)] == [
        'serial low-latency on (latency_timer 1 ms)']


def test_usb_latency_timer_reads_sysfs_or_returns_empty(tmp_path):
    assert bmcu_transportd._usb_latency_timer(str(tmp_path / 'ttyNOPE9')) == ''


def test_restarted_daemon_feed_starts_a_new_operation(tmp_path, sim):
    first = Harness(tmp_path, sim, rng=random.Random(1))
    try:
        client = first.connect()
        first.wait_ready()
        client.send(protocol.MSG_FEED_DISTANCE, 400, FEED)
        assert wait_until(lambda: client.packets(protocol.MSG_ACK, 400))
        sim.complete_operation(sim.operations_started[-1])
        assert wait_until(lambda: client.packets(protocol.MSG_OP_RESULT, 400))
    finally:
        first.stop()
    # The sim, like the firmware, keeps its operation history across sessions.
    second = Harness(tmp_path, sim, rng=random.Random(2))
    try:
        client = second.connect()
        second.wait_ready()
        client.send(protocol.MSG_FEED_DISTANCE, 400, FEED)
        assert wait_until(lambda: client.packets(protocol.MSG_ACK, 400))
        assert len(set(sim.operations_started)) == 2
        time.sleep(0.1)
        assert not client.packets(protocol.MSG_OP_RESULT, 400)
    finally:
        second.stop()


class RecordingRandrange(random.Random):
    def __init__(self, value):
        random.Random.__init__(self, 3)
        self.value = value
        self.calls = []

    def randrange(self, start, stop):
        self.calls.append((start, stop))
        return self.value


def test_external_wire_ids_start_from_the_rng(tmp_path, sim):
    rng = RecordingRandrange(123456789)
    h = Harness(tmp_path, sim, rng=rng)
    try:
        client = h.connect()
        h.wait_ready()
        assert rng.calls == [(1, 0xF0000000)]
        client.send(protocol.MSG_PING, 7, b'a')
        client.send(protocol.MSG_PING, 8, b'b')
        assert wait_until(lambda: client.packets(protocol.MSG_PONG, 8))
        wire = sim.frames('rx', protocol.MSG_PING)
        assert [f.cmd_id for f in wire] == [123456789, 123456790]
    finally:
        h.stop()


def test_external_wire_ids_wrap_below_internal_base():
    args = argparse.Namespace()
    daemon = bmcu_transportd.TransportDaemon(args, RecordingRandrange(0xEFFFFFFF))
    assert [daemon._next_external_cmd() for _ in range(3)] == [0xEFFFFFFF, 1, 2]


def test_default_rngs_give_daemons_different_wire_starts():
    args = argparse.Namespace()
    starts = {bmcu_transportd.TransportDaemon(args).external_cmd for _ in range(8)}
    assert len(starts) > 1
    assert all(1 <= value < 0xF0000000 for value in starts)



def test_partial_frame_age_restarts_after_a_truncated_frame(start, sim):
    h = start_half_duplex(start)
    h.wait_ready()
    first = protocol.encode_packet(protocol.MSG_STATUS, 910, 0, sim.status_payload())
    second = protocol.encode_packet(protocol.MSG_STATUS, 911, 0, sim.status_payload())
    sim.send_raw(first[:20])
    assert wait_until(lambda: h.daemon.serial_decoder.pending)
    errors = h.daemon.serial_decoder.errors
    between = time.monotonic()
    # The first frame lost its terminator: the second frame's leading
    # delimiter ends it as a decode error and a new partial frame begins.
    sim.send_raw(second[:20])
    assert wait_until(lambda: h.daemon.serial_decoder.errors > errors)
    assert h.daemon.serial_decoder.pending
    assert h.daemon.partial_since >= between


def test_half_duplex_write_waits_for_rx_quiet_time(start, sim):
    h = start_half_duplex(start, rx_quiet_ms=40.0, resend_timeout=1.0)
    client = h.connect()
    h.wait_ready()
    statuses = h.daemon.latest_status
    sim.send_status()
    assert wait_until(lambda: h.daemon.latest_status is not statuses)
    client.send(protocol.MSG_PING, 83, b'q')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 83))
    status_sent = sim.frames('tx', protocol.MSG_STATUS)[-1].time
    assert sim.frames('rx', protocol.MSG_PING)[-1].time - status_sent >= 0.04


def test_rx_quiet_time_is_capped_by_the_write_gate_bound(start, sim):
    h = start_half_duplex(start, rx_quiet_ms=5000.0, resend_timeout=1.0)
    client = h.connect()
    h.wait_ready()
    statuses = h.daemon.latest_status
    sim.send_status()
    assert wait_until(lambda: h.daemon.latest_status is not statuses)
    client.send(protocol.MSG_PING, 84, b'c')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 84), 1.0)
    status_sent = sim.frames('tx', protocol.MSG_STATUS)[-1].time
    assert sim.frames('rx', protocol.MSG_PING)[-1].time - status_sent < 0.25


def test_parse_args_rx_quiet_default(monkeypatch):
    monkeypatch.setattr('sys.argv', [
        'bmcu_transportd', '--name', 'n', '--port', '/dev/null', '--socket', '/tmp/s',
        '--log-file', '/tmp/l', '--status-file', '/tmp/f'])
    assert bmcu_transportd.parse_args().rx_quiet_ms == 2.0


class PipeSerial(object):
    def __init__(self):
        self.read_fd, self.write_fd = os.pipe()
        os.set_blocking(self.read_fd, False)

    def fileno(self):
        return self.write_fd

    def drain(self):
        try:
            return os.read(self.read_fd, 65536)
        except BlockingIOError:
            return b''

    def close(self):
        os.close(self.read_fd)
        os.close(self.write_fd)


def flush_daemon(half_duplex):
    args = argparse.Namespace(half_duplex=half_duplex, resend_timeout=0.25,
                              resend_attempts=3, rx_quiet_ms=2.0)
    daemon = bmcu_transportd.TransportDaemon(args, random.Random(1))
    daemon.serial = PipeSerial()
    frames = []
    for index in range(3):
        before = len(daemon.serial_tx)
        daemon._queue_serial(protocol.MSG_PING, 50 + index, b'x')
        frames.append(bytes(daemon.serial_tx[before:]))
    return daemon, frames


def test_half_duplex_flush_writes_one_frame_per_pass():
    daemon, frames = flush_daemon(True)
    try:
        daemon._flush_serial()
        assert daemon.serial.drain() == frames[0]
        daemon._flush_serial()
        assert daemon.serial.drain() == frames[1]
        daemon._flush_serial()
        assert daemon.serial.drain() == frames[2]
        assert not daemon.serial_tx and not daemon.serial_tx_frames
    finally:
        daemon.serial.close()


def test_full_duplex_flush_writes_the_whole_queue():
    daemon, frames = flush_daemon(False)
    try:
        daemon._flush_serial()
        assert daemon.serial.drain() == b''.join(frames)
    finally:
        daemon.serial.close()


def test_half_duplex_resend_timer_starts_when_the_frame_is_written():
    args = argparse.Namespace(half_duplex=True, resend_timeout=0.25,
                              resend_attempts=3, rx_quiet_ms=2.0)
    daemon = bmcu_transportd.TransportDaemon(args, FixedUniform('low'))
    daemon.serial = PipeSerial()
    try:
        cmd = daemon._queue_internal(protocol.MSG_GET_SNAPSHOT, b'', 'snapshot')
        queued = len(daemon.serial_tx)
        # Still unsent: no amount of waiting makes it due.
        daemon._service_resends(time.monotonic() + 10.0)
        assert len(daemon.serial_tx) == queued
        before = time.monotonic()
        daemon._flush_serial()
        after = time.monotonic()
        due = daemon.resend[cmd]['due']
        assert before + 0.2 <= due <= after + 0.2
        daemon._service_resends(due - 0.01)
        assert not daemon.serial_tx
        daemon._service_resends(due)
        assert daemon.serial_tx and daemon.resend[cmd]['sends'] == 2
        assert daemon.resend[cmd]['due'] is None
    finally:
        daemon.serial.close()


def motion_frames(sim, channel=None):
    return [f for f in sim.frames('rx', protocol.MSG_SET_MOTION)
            if channel is None or f.payload[0] == channel]


def test_half_duplex_lost_motion_is_not_resent_after_stop_all(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_SET_MOTION)
    client.send(protocol.MSG_SET_MOTION, 500, bytes([1, protocol.MOTION_SEND_OUT]))
    client.send(protocol.MSG_STOP_ALL, 501)
    assert wait_until(lambda: client.packets(protocol.MSG_ACK, 501))
    time.sleep(0.4)
    assert len(motion_frames(sim)) == 1
    assert sim.motion == [protocol.MOTION_IDLE] * 4
    assert not client.packets(protocol.MSG_ACK, 500)


def test_half_duplex_lost_stop_all_is_still_resent_after_a_newer_operation(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_STOP_ALL)
    client.send(protocol.MSG_STOP_ALL, 502)
    client.send(protocol.MSG_FEED_DISTANCE, 503, FEED)
    assert wait_until(lambda: client.packets(protocol.MSG_ACK, 502))
    assert len(sim.frames('rx', protocol.MSG_STOP_ALL)) == 2
    # The stop lands after the operation, so the operation is aborted.
    result = wait_until(lambda: client.packets(protocol.MSG_OP_RESULT, 503))
    assert result and protocol.parse_op_result(result[0][4])['state'] == \
        protocol.OP_STATE_ABORTED


def test_half_duplex_lost_stop_all_alone_is_resent(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_STOP_ALL)
    client.send(protocol.MSG_STOP_ALL, 504)
    assert wait_until(lambda: client.packets(protocol.MSG_ACK, 504))
    assert len(sim.frames('rx', protocol.MSG_STOP_ALL)) == 2


def test_half_duplex_newer_motion_drops_an_older_motion_resend(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_SET_MOTION)
    client.send(protocol.MSG_SET_MOTION, 505, bytes([0, protocol.MOTION_SEND_OUT]))
    client.send(protocol.MSG_SET_MOTION, 506, bytes([2, protocol.MOTION_PULL_BACK]))
    assert wait_until(lambda: client.packets(protocol.MSG_ACK, 506))
    time.sleep(0.4)
    assert len(motion_frames(sim, 0)) == 1
    assert sim.motion[0] == protocol.MOTION_IDLE
    assert sim.motion[2] == protocol.MOTION_PULL_BACK


def test_half_duplex_concurrent_reads_both_recover(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_GET_STATUS, count=2)
    client.send(protocol.MSG_GET_STATUS, 507)
    client.send(protocol.MSG_GET_STATUS, 508)
    assert wait_until(lambda: client.packets(protocol.MSG_STATUS, 507) and
                      client.packets(protocol.MSG_STATUS, 508))
    assert len(sim.frames('rx', protocol.MSG_GET_STATUS)) == 4


def test_half_duplex_read_does_not_drop_a_motion_resend(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_SET_MOTION)
    client.send(protocol.MSG_SET_MOTION, 509, bytes([3, protocol.MOTION_SEND_OUT]))
    client.send(protocol.MSG_PING, 510, b'r')
    assert wait_until(lambda: client.packets(protocol.MSG_ACK, 509))
    assert sim.motion[3] == protocol.MOTION_SEND_OUT


def test_half_duplex_motion_does_not_drop_a_read_resend(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_GET_STATUS)
    client.send(protocol.MSG_GET_STATUS, 511)
    client.send(protocol.MSG_SET_MOTION, 512, bytes([1, protocol.MOTION_SEND_OUT]))
    assert wait_until(lambda: client.packets(protocol.MSG_STATUS, 511))


def test_half_duplex_update_prepare_drops_the_update_cancel_resend(start, sim):
    sim.add_fault('ignore', protocol.MSG_UPDATE_CANCEL)
    h = start_half_duplex(start, resend_timeout=0.3)
    client = h.connect()
    assert wait_until(lambda: h.daemon.session_ready)
    client.send(protocol.MSG_UPDATE_PREPARE, 513)
    assert wait_until(lambda: client.packets(protocol.MSG_ACK, 513))
    time.sleep(0.5)
    assert len(sim.frames('rx', protocol.MSG_UPDATE_CANCEL)) == 1
    cancel = sim.frames('rx', protocol.MSG_UPDATE_CANCEL)[0]
    prepare = sim.frames('rx', protocol.MSG_UPDATE_PREPARE)[0]
    assert prepare.time > cancel.time


def test_half_duplex_duplicate_reply_to_a_plain_request_is_dropped(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    client.send(protocol.MSG_FEED_DISTANCE, 520, FEED)
    assert wait_until(lambda: client.packets(protocol.MSG_ACK, 520))
    # The operation is still running, so the query reaches the BMCU, which
    # answers it twice: the delayed original and the resend.
    sim.add_fault('delay', protocol.MSG_GET_OP_RESULT, seconds=0.2)
    client.send(protocol.MSG_GET_OP_RESULT, 521, struct.pack('<I', 520))
    assert wait_until(lambda: len(sim.frames('tx', protocol.MSG_ERROR)) >= 2, 1.0)
    client.send(protocol.MSG_PING, 522, b'sync')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 522))
    assert len(client.packets(protocol.MSG_ERROR, 521)) == 1
    assert not client.packets(protocol.MSG_ERROR, 0)


def test_half_duplex_answered_ids_expire(start, sim, monkeypatch):
    monkeypatch.setattr(bmcu_transportd, '_ANSWERED_TTL', 0.2)
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    client.send(protocol.MSG_PING, 523, b'e')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 523))
    assert h.daemon.answered
    assert wait_until(lambda: not h.daemon.answered, 1.0)


def test_full_duplex_keeps_no_answered_ids(start, sim):
    h = start()
    client = h.connect()
    h.wait_ready()
    client.send(protocol.MSG_PING, 524, b'f')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 524))
    assert not h.daemon.answered


def test_half_duplex_duplicate_error_to_an_operation_is_dropped(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('delay', protocol.MSG_FEED_DISTANCE, seconds=0.2)
    client.send(protocol.MSG_FEED_DISTANCE, 525, struct.pack('<BfBI', 7, 100.0, 0, 5000))
    assert wait_until(lambda: len(sim.frames('tx', protocol.MSG_ERROR)) >= 2, 1.0)
    client.send(protocol.MSG_PING, 526, b'sync')
    assert wait_until(lambda: client.packets(protocol.MSG_PONG, 526))
    assert len(client.packets(protocol.MSG_ERROR, 525)) == 1
    assert not client.packets(protocol.MSG_ERROR, 0)


def test_half_duplex_newer_stop_drops_an_older_stop_resend(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_STOP_ALL)
    client.send(protocol.MSG_STOP_ALL, 530)
    client.send(protocol.MSG_ABORT_OP, 531)
    assert wait_until(lambda: client.packets(protocol.MSG_ACK, 531))
    time.sleep(0.4)
    assert len(sim.frames('rx', protocol.MSG_STOP_ALL)) == 1


def test_half_duplex_update_prepare_drops_an_abort_resend(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_ABORT_OP)
    client.send(protocol.MSG_ABORT_OP, 532)
    client.send(protocol.MSG_UPDATE_PREPARE, 533)
    assert wait_until(lambda: client.packets(protocol.MSG_ACK, 533))
    time.sleep(0.4)
    assert len(sim.frames('rx', protocol.MSG_ABORT_OP)) == 1


def test_half_duplex_stop_drops_a_read_resend(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_GET_STATUS)
    client.send(protocol.MSG_GET_STATUS, 534)
    client.send(protocol.MSG_STOP_ALL, 535)
    assert wait_until(lambda: client.packets(protocol.MSG_ACK, 535))
    time.sleep(0.4)
    assert len(sim.frames('rx', protocol.MSG_GET_STATUS)) == 1


def test_half_duplex_stop_resend_keeps_a_newer_read_resend(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_STOP_ALL)
    sim.add_fault('ignore', protocol.MSG_GET_STATUS)
    client.send(protocol.MSG_STOP_ALL, 536)
    client.send(protocol.MSG_GET_STATUS, 537)
    assert wait_until(lambda: client.packets(protocol.MSG_ACK, 536) and
                      client.packets(protocol.MSG_STATUS, 537))


@pytest.mark.parametrize('event,payload', [
    (protocol.MSG_STATE_CHANGED, b'\x01'),
    (protocol.MSG_MOTION_DONE, b'\x01'),
    (protocol.MSG_JAM, b'\x01\x00\x00'),
    (protocol.MSG_ERROR, struct.pack('<BHI', 1, 50, 0)),
])
def test_half_duplex_firmware_stop_event_drops_a_motion_resend(start, sim, event, payload):
    h = start_half_duplex(start, resend_timeout=0.4)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('drop', protocol.MSG_SET_MOTION)
    client.send(protocol.MSG_SET_MOTION, 540, bytes([1, protocol.MOTION_SEND_OUT]))
    assert wait_until(lambda: motion_frames(sim))
    sim.send(event, 0, payload)
    time.sleep(0.7)
    assert len(motion_frames(sim)) == 1


def test_half_duplex_firmware_stop_event_keeps_a_read_resend(start, sim):
    h = start_half_duplex(start, resend_timeout=0.4)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_GET_STATUS)
    client.send(protocol.MSG_GET_STATUS, 541)
    assert wait_until(lambda: sim.frames('rx', protocol.MSG_GET_STATUS))
    sim.send(protocol.MSG_STATE_CHANGED, 0, b'\x01')
    assert wait_until(lambda: client.packets(protocol.MSG_STATUS, 541), 1.5)


def test_half_duplex_error_reply_to_a_read_keeps_a_motion_resend(start, sim):
    h = start_half_duplex(start)
    client = h.connect()
    h.wait_ready()
    sim.add_fault('ignore', protocol.MSG_SET_MOTION)
    client.send(protocol.MSG_SET_MOTION, 542, bytes([2, protocol.MOTION_SEND_OUT]))
    # An unknown CONFIG_GET key draws an ERROR carrying its own cmd_id.
    client.send(protocol.MSG_CONFIG_GET, 543, struct.pack('<H', 0x7777))
    assert wait_until(lambda: client.packets(protocol.MSG_ERROR, 543))
    assert wait_until(lambda: client.packets(protocol.MSG_ACK, 542))


def test_select_timeout_waits_out_a_partial_frame():
    args = argparse.Namespace(half_duplex=True, resend_timeout=0.25,
                              resend_attempts=3, rx_quiet_ms=2.0)
    daemon = bmcu_transportd.TransportDaemon(args, random.Random(1))
    daemon.serial = object()
    daemon.serial_tx.extend(b'\x00\x01\x00')
    daemon.serial_decoder.feed(b'\x00\x05\x01')
    now = time.monotonic()
    daemon.last_rx_byte = daemon.partial_since = now - 0.01
    assert daemon._write_gated(now)
    assert daemon._select_timeout(now) == pytest.approx(0.04, abs=0.002)
