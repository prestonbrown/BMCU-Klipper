# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
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
    def __init__(self, tmp_path, sim, **overrides):
        self.sim = sim
        lock = open(str(tmp_path / 'transport.lock'), 'w+')
        options = dict(
            name='bmcu_test', port=sim.port, expected_uid='',
            scan_fallback=False, exclude_ports=(),
            socket=str(tmp_path / 'bmcu.sock'), baud=115200,
            heartbeat=5.0, connection_timeout=15.0, reconnect=0.1,
            status_interval=0.5, connect_settle=0.0,
            status_file=str(tmp_path / 'status.json'),
            settings_digest='', lifetime_lock=lock, process_record={})
        options.update(overrides)
        self.args = argparse.Namespace(**options)
        self.daemon = bmcu_transportd.TransportDaemon(self.args)
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
