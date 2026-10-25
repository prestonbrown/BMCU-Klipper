# SPDX-License-Identifier: GPL-3.0-or-later

"""Simulated BMCU on the master side of a pty.

The slave path is handed to the transport daemon as its serial port. The
simulator answers the host the way firmware/src/bmcu_protocol.cpp does: the
HELLO / SESSION_CONFIRM handshake, sequence tracking with silent drop of
non-advancing seq numbers, and replies keyed on the request's cmd_id. Every
frame in either direction is logged with a time.monotonic() timestamp, and
faults can be armed per request type.
"""

import collections
import heapq
import os
import select
import struct
import threading
import time
import tty
import zlib

from bmcu_core import protocol
from bmcu_core.release import REQUIRED_FIRMWARE

DEFAULT_UID = bytes(range(0x11, 0x1d))

ERR_SESSION = 96
ERR_LENGTH = 100
ERR_UNKNOWN = 0xffff

# Fixed payload sizes from command_payload_size() in the firmware; -2 means
# variable up to 128 bytes.
_PAYLOAD_SIZE = {
    protocol.MSG_HELLO: 4, protocol.MSG_SESSION_CONFIRM: 4,
    protocol.MSG_PING: -2, protocol.MSG_GET_STATUS: 0,
    protocol.MSG_GET_CAPS: 0, protocol.MSG_GET_SNAPSHOT: 0,
    protocol.MSG_GET_OP_RESULT: 4, protocol.MSG_ABORT_OP: 0,
    protocol.MSG_UPDATE_CANCEL: 0, protocol.MSG_STOP_ALL: 0,
    protocol.MSG_RESET_ERROR: 0, protocol.MSG_SET_ACTIVE_CH: 1,
}

Frame = collections.namedtuple(
    'Frame', 'direction time msg_type seq cmd_id payload raw note')


class Fault(object):
    """One armed fault, consumed by the next `count` requests of `msg_type`.

    action is one of:
      'drop'     the reply is never sent;
      'corrupt'  the reply is sent with one encoded byte flipped (CRC fails);
      'delay'    the reply is sent `seconds` later;
      'ignore'   the request itself is discarded before seq tracking, as if
                 it never arrived;
      'status_before'  an unsolicited STATUS(cmd_id=0) is sent immediately
                 before the reply.
    msg_type None matches any request.
    """

    def __init__(self, action, msg_type=None, count=1, seconds=0.0):
        self.action = action
        self.msg_type = msg_type
        self.count = count
        self.seconds = seconds

    def matches(self, msg_type):
        return self.count != 0 and (self.msg_type is None or
                                    self.msg_type == msg_type)


class BmcuSim(object):
    def __init__(self, uid=DEFAULT_UID, firmware=REQUIRED_FIRMWARE,
                 capabilities=0):
        self.uid = bytes(uid)
        self.firmware = tuple(firmware)
        self.capabilities = int(capabilities)
        self.master_fd, self._slave_fd = os.openpty()
        tty.setraw(self._slave_fd)
        os.set_blocking(self.master_fd, False)
        self.port = os.ttyname(self._slave_fd)
        self._wake_r, self._wake_w = os.pipe()
        os.set_blocking(self._wake_r, False)

        self.lock = threading.RLock()
        self.log = []
        self.faults = []
        self.handlers = {
            protocol.MSG_PING: self._on_ping,
            protocol.MSG_GET_STATUS: self._on_get_status,
            protocol.MSG_GET_SNAPSHOT: self._on_get_snapshot,
            protocol.MSG_UPDATE_CANCEL: self._on_ack,
            protocol.MSG_ABORT_OP: self._on_ack,
            protocol.MSG_STOP_ALL: self._on_ack,
            protocol.MSG_RESET_ERROR: self._on_ack,
            protocol.MSG_SET_ACTIVE_CH: self._on_set_active_ch,
        }
        self.decoder = protocol.StreamDecoder()
        self.silent = False
        self.duplicates = 0

        self.seq_tx = 1
        self.seq_rx_last = 0
        self.session_id = 0
        self.host_session_ready = False
        self.event_counter = 1
        self.now_channel = 0xff
        self.present = [0, 0, 0, 0]
        self._rotate_session(0)

        self._outbox = []
        self._outbox_order = 0
        self._running = True
        self._thread = threading.Thread(target=self._run, name='bmcu-sim',
                                        daemon=True)
        self._thread.start()

    def close(self):
        self._running = False
        self._wake()
        self._thread.join(2.0)
        for fd in (self.master_fd, self._slave_fd, self._wake_r, self._wake_w):
            try:
                os.close(fd)
            except OSError:
                pass

    # Fault injection.

    def add_fault(self, action, msg_type=None, count=1, seconds=0.0):
        fault = Fault(action, msg_type, count, seconds)
        with self.lock:
            self.faults.append(fault)
        return fault

    def _take_fault(self, msg_type, actions):
        with self.lock:
            for fault in self.faults:
                if fault.action in actions and fault.matches(msg_type):
                    if fault.count > 0:
                        fault.count -= 1
                    return fault
        return None

    # Device state.

    def _rotate_session(self, nonce):
        value = zlib.crc32(self.uid + struct.pack(
            '<III', self.session_id, nonce, int(time.monotonic() * 1e6) & 0xffffffff))
        self.session_id = (value & 0xffffffff) or 1

    def status_payload(self):
        return struct.pack(
            '<B4B4B4B4BB4BBBH4f4f4hIII4B6B',
            self.now_channel,
            *([protocol.ROUTE_EMPTY] * 4),
            *([protocol.MOTION_IDLE] * 4),
            *self.present,
            *([50] * 4),
            0x0f,
            *([0] * 4),
            0x0f, 0x0f, 0,
            *([0.0] * 4),
            *([1.65] * 4),
            *([0] * 4),
            self.session_id, self.event_counter, 0,
            0, 0xff, protocol.OP_STATE_IDLE, 0,
            0, 0, 0, 0, protocol.OP_STATE_IDLE, 0)

    def snapshot_payload(self):
        payload = self.status_payload()
        for channel in range(4):
            payload += struct.pack('<BBBbfffff', channel, 0, 0, 1,
                                   1.65, 0.0, 0.0, 0.0, 0.0)
        return payload

    def hello_payload(self):
        return struct.pack(
            '<12sBBBBIIBB', self.uid, self.firmware[0], self.firmware[1],
            self.firmware[2], protocol.PROTO_VERSION, self.capabilities,
            self.session_id, 4, 50)

    def set_present(self, channel, value, notify=True):
        """Change a filament-present flag; like process_events(), a change
        sends an unsolicited STATUS."""
        with self.lock:
            self.present[channel] = 1 if value else 0
            self.event_counter += 1
            if notify:
                self.send_status()

    def send_status(self, cmd_id=0, delay=0.0):
        self.send(protocol.MSG_STATUS, cmd_id, self.status_payload(),
                  delay=delay)

    # Transmit.

    def encode(self, msg_type, cmd_id, payload=b''):
        with self.lock:
            seq = self.seq_tx
            self.seq_tx = (self.seq_tx + 1) & 0xffffffff
        return seq, protocol.encode_packet(msg_type, seq, cmd_id, payload)

    def send(self, msg_type, cmd_id, payload=b'', delay=0.0, corrupt=False):
        seq, raw = self.encode(msg_type, cmd_id, payload)
        note = ''
        if corrupt:
            raw = corrupt_frame(raw)
            note = 'corrupt'
        self.send_raw(raw, delay=delay, frame=(msg_type, seq, cmd_id,
                                               bytes(payload), note))

    def send_raw(self, raw, delay=0.0, frame=None):
        """Queue bytes for the wire. `frame` describes them for the log."""
        with self.lock:
            self._outbox_order += 1
            heapq.heappush(self._outbox, (time.monotonic() + delay,
                                          self._outbox_order, bytes(raw), frame))
        self._wake()

    def _wake(self):
        try:
            os.write(self._wake_w, b'.')
        except OSError:
            pass

    def _flush_due(self):
        now = time.monotonic()
        while True:
            with self.lock:
                if not self._outbox or self._outbox[0][0] > now:
                    return
                _due, _order, raw, frame = heapq.heappop(self._outbox)
            os.write(self.master_fd, raw)
            if frame is None:
                frame = (None, None, None, b'', 'raw')
            msg_type, seq, cmd_id, payload, note = frame
            self._record('tx', msg_type, seq, cmd_id, payload, raw, note)

    def _record(self, direction, msg_type, seq, cmd_id, payload, raw, note=''):
        with self.lock:
            self.log.append(Frame(direction, time.monotonic(), msg_type, seq,
                                  cmd_id, bytes(payload), bytes(raw), note))

    # Receive.

    def _run(self):
        while self._running:
            with self.lock:
                timeout = 0.05
                if self._outbox:
                    timeout = max(0.0, min(timeout, self._outbox[0][0] - time.monotonic()))
            try:
                readable, _w, _x = select.select(
                    [self.master_fd, self._wake_r], [], [], timeout)
            except (OSError, ValueError):
                return
            if self._wake_r in readable:
                try:
                    os.read(self._wake_r, 4096)
                except OSError:
                    pass
            if self.master_fd in readable:
                try:
                    data = os.read(self.master_fd, 4096)
                except BlockingIOError:
                    data = b''
                except OSError:
                    # EIO while no slave is open; the daemon is reconnecting.
                    time.sleep(0.01)
                    data = b''
                if data:
                    for packet in self.decoder.feed(data):
                        self.handle_packet(*packet)
            self._flush_due()

    def handle_packet(self, msg_type, seq, cmd_id, payload):
        """Process one decoded host frame as handle_packet() does in firmware."""
        raw = protocol.encode_packet(msg_type, seq, cmd_id, payload)
        self._record('rx', msg_type, seq, cmd_id, payload, raw)
        if self._take_fault(msg_type, ('ignore',)) is not None:
            self._record('drop', msg_type, seq, cmd_id, payload, raw, 'ignored')
            return
        if self.silent:
            return
        replies = self._dispatch(msg_type, seq, cmd_id, payload)
        if not replies:
            return
        if self._take_fault(msg_type, ('drop',)) is not None:
            for reply in replies:
                self._record('drop', reply[0], None, reply[1], reply[2], b'',
                             'dropped reply')
            return
        delay = 0.0
        fault = self._take_fault(msg_type, ('delay',))
        if fault is not None:
            delay = fault.seconds
        if self._take_fault(msg_type, ('status_before',)) is not None:
            self.send_status(0, delay=delay)
        corrupt = self._take_fault(msg_type, ('corrupt',)) is not None
        for reply_type, reply_cmd, reply_payload in replies:
            self.send(reply_type, reply_cmd, reply_payload, delay=delay,
                      corrupt=corrupt)
            corrupt = False

    def _dispatch(self, msg_type, seq, cmd_id, payload):
        expected = _PAYLOAD_SIZE.get(msg_type)
        if expected is None and msg_type not in self.handlers:
            return [error_reply(cmd_id, ERR_UNKNOWN)]
        if expected is not None and ((expected >= 0 and len(payload) != expected) or
                                     (expected == -2 and len(payload) > 128)):
            return [error_reply(cmd_id, ERR_LENGTH)]

        if msg_type == protocol.MSG_HELLO:
            nonce = struct.unpack('<I', payload)[0]
            with self.lock:
                self.host_session_ready = False
                self._outbox[:] = []
                self._rotate_session(nonce)
            return [(protocol.MSG_HELLO_ACK, cmd_id, self.hello_payload())]

        if msg_type == protocol.MSG_SESSION_CONFIRM:
            if struct.unpack('<I', payload)[0] != self.session_id:
                return [error_reply(cmd_id, ERR_SESSION)]
            if not self.host_session_ready:
                self.host_session_ready = True
                self.seq_rx_last = seq
            return [ack_reply(cmd_id)]

        if not self.host_session_ready:
            return [error_reply(cmd_id, ERR_SESSION)]
        delta = (seq - self.seq_rx_last) & 0xffffffff
        if not delta or delta >= 0x80000000:
            self.duplicates += 1
            self._record('drop', msg_type, seq, cmd_id, payload, b'',
                         'stale seq')
            return []
        self.seq_rx_last = seq
        return list(self.handlers[msg_type](cmd_id, payload))

    # Request handlers: each returns (msg_type, cmd_id, payload) replies.

    def _on_ping(self, cmd_id, payload):
        return [(protocol.MSG_PONG, cmd_id, payload)]

    def _on_get_status(self, cmd_id, _payload):
        return [(protocol.MSG_STATUS, cmd_id, self.status_payload())]

    def _on_get_snapshot(self, cmd_id, _payload):
        return [(protocol.MSG_SNAPSHOT, cmd_id, self.snapshot_payload())]

    def _on_ack(self, cmd_id, _payload):
        return [ack_reply(cmd_id)]

    def _on_set_active_ch(self, cmd_id, payload):
        if payload[0] >= 4:
            return [error_reply(cmd_id, 2)]
        self.now_channel = payload[0]
        return [ack_reply(cmd_id),
                (protocol.MSG_STATUS, 0, self.status_payload())]

    # Log queries.

    def frames(self, direction, msg_type=None):
        with self.lock:
            return [frame for frame in self.log
                    if frame.direction == direction and
                    (msg_type is None or frame.msg_type == msg_type)]

    def wait_for(self, predicate, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.005)
        return predicate()


def ack_reply(cmd_id, ok=1, error=0):
    return (protocol.MSG_ACK, cmd_id, struct.pack('<IBH', cmd_id, ok, error))


def error_reply(cmd_id, error, channel=0xff):
    return (protocol.MSG_ERROR, cmd_id, struct.pack('<BHI', channel, error, 0))


def corrupt_frame(raw):
    """Flip one byte inside the COBS body without creating a delimiter."""
    raw = bytearray(raw)
    index = len(raw) // 2
    value = raw[index] ^ 0x55
    raw[index] = value if value else 0xaa
    return bytes(raw)
