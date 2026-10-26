#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import collections
import errno
import glob
import fcntl
import logging
import logging.handlers
import json
import os
import random
import select
import signal
import socket
import stat
import struct
import sys
import termios
import time

HERE = os.path.dirname(os.path.realpath(__file__))
RUNTIME = os.path.dirname(HERE)
EXTRAS = os.path.join(RUNTIME, 'klippy', 'extras')
VENDOR = os.path.join(RUNTIME, 'vendor', 'pyserial-3.5-py2.py3-none-any.whl')
for entry in (EXTRAS, VENDOR):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from bmcu_core import protocol, transport

_INTERNAL_BASE = 0xF0000000
_MAX_SERIAL_TX = 256 * 1024
_MAX_CLIENT_TX = 512 * 1024
_MAX_RELIABLE = 1024
_MAX_EXTERNAL_PENDING = 2048
_EXTERNAL_TIMEOUT = 310.0
_COMPLETED_OPERATION_TTL = 310.0
_OPERATION_START_TYPES = frozenset((
    protocol.MSG_TEST_ENCODER, protocol.MSG_CHANNEL_AUTOLOAD,
    protocol.MSG_FEED_TO_CONTACT, protocol.MSG_FEED_DISTANCE,
    protocol.MSG_CHANNEL_RETRACT, protocol.MSG_CAL_AUTO_START,
))
# Half-duplex resend covers these internal requests; HELLO has its own retry
# and the heartbeat its own expiry.
_RESEND_PURPOSES = frozenset(('confirm', 'resume_update', 'snapshot'))
# A resent preload finds its own motion running and answers error 40, so a
# preload that started would be reported as failed.
_NO_RESEND_TYPES = frozenset((protocol.MSG_CHANNEL_PRELOAD,))
# A late resend must never run after a newer command and undo it. Queuing one
# of these stop/reset requests drops every pending resend; queuing any other
# state-changing request drops the pending resends of state-changing requests
# other than stops, which only a newer stop supersedes.
_STOP_TYPES = frozenset((
    protocol.MSG_STOP_ALL, protocol.MSG_ABORT_OP, protocol.MSG_RESET_ERROR,
    protocol.MSG_UPDATE_PREPARE,
))
# Requests that change nothing on the BMCU (the handshake frames included);
# they neither drop resends nor are dropped.
_PASSIVE_TYPES = frozenset((
    protocol.MSG_PING, protocol.MSG_GET_STATUS, protocol.MSG_GET_CAPS,
    protocol.MSG_GET_CALIBRATION, protocol.MSG_GET_OP_RESULT,
    protocol.MSG_GET_SLOT_INFO, protocol.MSG_CONFIG_GET, protocol.MSG_NVM_READ,
    protocol.MSG_GET_SNAPSHOT, protocol.MSG_HELLO, protocol.MSG_SESSION_CONFIRM,
))
# Unsolicited (cmd 0) firmware events that report a stop or fault. They make
# pending resends stale the way a newer host state change does: a resent
# SET_MOTION would otherwise restart a motor the firmware just stopped.
_FIRMWARE_STOP_EVENTS = frozenset((
    protocol.MSG_JAM, protocol.MSG_STATE_CHANGED, protocol.MSG_MOTION_DONE,
    protocol.MSG_ERROR,
))
# Half-duplex writes wait at most this long for a partial inbound frame to
# finish, so line noise cannot hold transmit forever.
_WRITE_GATE_MAX = 0.05
# How long a half-duplex daemon remembers that a plain request was answered,
# so a late duplicate reply (to the original and to its resend) is dropped
# instead of reaching Klipper as an unsolicited packet.
_ANSWERED_TTL = 5.0
_MAX_ANSWERED = 4096
# Each resend wait is resend_timeout scaled by a factor drawn from this range,
# so host retries cannot phase-lock with the firmware's periodic STATUS.
_RESEND_JITTER = (0.8, 1.2)
# Linux struct serial_struct in native layout (72 bytes on 64-bit, 60 on
# 32-bit); flags is the fifth int. ftdi_sio maps ASYNC_LOW_LATENCY to a 1 ms
# latency timer, which lets the half-duplex write gate see an inbound frame
# almost as soon as it starts.
_SERIAL_STRUCT = struct.Struct('@iiIiiiiiHcciHHPHIL')
_SERIAL_FLAGS_OFFSET = struct.calcsize('@iiIi')
_ASYNC_LOW_LATENCY = 0x2000
_TIOCGSERIAL = getattr(termios, 'TIOCGSERIAL', 0x541E)
_TIOCSSERIAL = getattr(termios, 'TIOCSSERIAL', 0x541F)
_serial_ioctl = fcntl.ioctl


def request_low_latency(fd):
    """Set ASYNC_LOW_LATENCY on a tty; returns None or why it was not set."""
    buffer = bytearray(_SERIAL_STRUCT.size)
    try:
        _serial_ioctl(fd, _TIOCGSERIAL, buffer, True)
        flags = struct.unpack_from('@i', buffer, _SERIAL_FLAGS_OFFSET)[0]
        if flags & _ASYNC_LOW_LATENCY:
            return None
        struct.pack_into('@i', buffer, _SERIAL_FLAGS_OFFSET,
                         flags | _ASYNC_LOW_LATENCY)
        _serial_ioctl(fd, _TIOCSSERIAL, buffer, False)
    except OSError as exc:
        return exc.strerror or str(exc)
    return None


def _usb_latency_timer(port):
    path = os.path.join('/sys/bus/usb-serial/devices',
                        os.path.basename(os.path.realpath(port)), 'latency_timer')
    try:
        with open(path) as stream:
            return stream.read(16).strip()
    except OSError:
        return ''

class TransportDaemon(object):
    def __init__(self, args, rng=None):
        self.args = args
        self.rng = rng if rng is not None else random.Random()
        self.running = True
        self.listener = None
        self.control = None
        self.client = None
        self.client_decoder = transport.MessageDecoder()
        self.client_tx = bytearray()
        self.client_paused = False
        self.client_control_only = False
        self.client_epoch = 0
        self.client_seq = 1

        self.external_pending = {}
        self.operation_wire_by_client = {}
        # The firmware replays a remembered result for an operation whose
        # op_id (the wire cmd_id) it has seen since boot, whatever the
        # session, so each daemon starts its wire ids at a random point.
        self.external_cmd = self.rng.randrange(1, _INTERNAL_BASE)
        self.reliable = collections.deque()
        self.latest_status = None
        self.latest_snapshot = None
        self.latest_hello = None
        self.latest_caps = None
        self.last_status_sent = 0.0
        self.serial = None
        self.current_port = ''
        self.last_good_port = ''
        self.serial_candidate_cursor = 0
        self.foreign_uid_until = {}
        self.serial_decoder = protocol.StreamDecoder()
        self.serial_tx = bytearray()
        # [unsent bytes, cmd_id] for each frame in serial_tx, oldest first.
        self.serial_tx_frames = collections.deque()
        self.partial_since = 0.0
        self.last_rx_byte = 0.0
        self.resend = {}
        self.answered = {}
        self.next_serial_connect = 0.0
        self.last_connect_error = ''
        self.serial_settle_until = 0.0
        self.serial_generation = 0
        self.seq = 1
        self.internal_cmd = _INTERNAL_BASE
        self.internal_pending = {}
        self.session_id = 0
        self.runtime_uid = ''
        self.session_ready = False
        self.hello_sent = False
        self.handshake_phase = 'idle'
        self.handshake_started_at = 0.0
        self.next_handshake_action = 0.0
        self.heartbeat_cmd = 0
        self.heartbeat_sent_at = 0.0
        self.serial_lease_fd = None
        self.serial_lease_path = ''
        self.last_serial_rx = 0.0
        self.last_serial_tx = 0.0
        self.last_keepalive = 0.0
        self.serial_released = False
        self.pending_local_hello = []
        self.pending_local_snapshot = []
        self.latest_status_dict = None
        self.last_semantic_status = None
        self.status_file_due = 0.0

    def setup(self):
        for path in (self.args.socket, self.args.socket + '.ctl', self.args.status_file):
            try:
                if os.path.lexists(path):
                    os.unlink(path)
            except OSError:
                pass
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.setblocking(False)
        self.listener.bind(self.args.socket)
        os.chmod(self.args.socket, 0o600)
        self.listener.listen(1)
        self.control = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.control.setblocking(False)
        self.control.bind(self.args.socket + '.ctl')
        os.chmod(self.args.socket + '.ctl', 0o600)

        self._write_status_file(force=True)
        self.args.process_record['ready'] = True
        self.args.lifetime_lock.seek(0)
        json.dump(self.args.process_record, self.args.lifetime_lock, sort_keys=True)
        self.args.lifetime_lock.truncate()
        self.args.lifetime_lock.flush()
        self.next_serial_connect = time.monotonic()

    def cleanup(self):
        self._drop_client()
        self._close_serial('shutdown', notify=False)
        for sock in (self.control, self.listener):
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        for path in (self.args.socket, self.args.socket + '.ctl', self.args.status_file):
            try:
                os.unlink(path)
            except OSError:
                pass

    def _next_seq(self):
        value = self.seq
        self.seq = (self.seq + 1) & 0xffffffff
        return value

    def _next_internal_cmd(self):
        value = self.internal_cmd
        self.internal_cmd = (self.internal_cmd + 1) & 0xffffffff
        if self.internal_cmd < _INTERNAL_BASE:
            self.internal_cmd = _INTERNAL_BASE
        return value

    def _next_external_cmd(self):

        value = self.external_cmd
        self.external_cmd += 1
        if self.external_cmd >= _INTERNAL_BASE:
            self.external_cmd = 1
        return value

    def _remove_external(self, wire_cmd):
        record = self.external_pending.pop(wire_cmd, None)
        if record and record.get('kind') in ('operation', 'operation_complete'):
            key = (record.get('epoch'), record.get('client_cmd'))
            if self.operation_wire_by_client.get(key) == wire_cmd:
                self.operation_wire_by_client.pop(key, None)
        return record

    @staticmethod
    def _rewrite_op_result_id(payload, op_id):
        if len(payload) < 4:
            return payload
        return struct.pack('<I', int(op_id) & 0xffffffff) + payload[4:]

    def _client_operation_id(self, wire_op):
        record = self.external_pending.get(wire_op)
        if (record is not None and
                record.get('epoch') == self.client_epoch and
                record.get('kind') in ('operation', 'operation_complete') and
                self.operation_wire_by_client.get(
                    (self.client_epoch, record.get('client_cmd'))) == wire_op):
            return int(record['client_cmd'])
        return 0

    @staticmethod
    def _semantic_status_fingerprint(status):
        auto_cal = status.get('auto_calibration', {}) or {}
        return (
            int(status.get('session_id', 0) or 0),
            tuple(int(v) for v in status.get('present', [0] * 4)),
            tuple(int(v) for v in status.get('motion', [0] * 4)),
            tuple(int(v) for v in status.get('route_state', [0] * 4)),
            int(status.get('connected_mask', 0) or 0),
            int(status.get('encoder_io_mask', 0) or 0),
            int(status.get('calibration_valid_mask', 0) or 0),
            int(status.get('active_op_id', 0) or 0),
            int(status.get('active_op_type', 0) or 0),
            int(status.get('active_op_state', 0) or 0),
            str(status.get('active_op_reason', '') or ''),
            int(status.get('error_flags', 0) or 0),
            bool(status.get('nvm_fault', False)),
            bool(auto_cal.get('active', False)),
            int(auto_cal.get('stage', 0) or 0),
            int(auto_cal.get('done_mask', 0) or 0),
            int(auto_cal.get('state', 0) or 0),
        )

    def _transport_status(self):
        return {
            'schema': 1, 'name': self.args.name, 'pid': os.getpid(),
            'online': bool(self.session_ready),
            'serial_released': bool(self.serial_released),
            'uid': self.runtime_uid,
            'serial_open': bool(self.serial is not None),
            'port': self.current_port or self.last_good_port or self.args.port,
            'expected_uid': self.args.expected_uid,
            'generation': int(self.serial_generation),
            'session_id': int(self.session_id),
            'updated_at': time.time(),
            'status': self.latest_status_dict,
        }

    def _write_status_file(self, force=False):
        path = self.args.status_file
        if not path:
            return
        now = time.monotonic()
        if not force and now < self.status_file_due:
            return
        self.status_file_due = now + 0.50
        value = self._transport_status()
        temporary = '%s.%d.tmp' % (path, os.getpid())
        try:
            with open(temporary, 'w') as stream:
                json.dump(value, stream, sort_keys=True, separators=(',', ':'))
                stream.write('\n')
                stream.flush()
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except Exception:
            logging.exception('could not publish live sidecar status')
            try:
                os.unlink(temporary)
            except OSError:
                pass

    def _queue_serial(self, msg_type, cmd_id, payload=b'', purpose=None,
                      resend=False):
        if self.serial is None:
            raise RuntimeError('serial transport is offline')
        if not resend:
            self._drop_superseded_resends(msg_type)
        frame = protocol.encode_packet(
            msg_type, self._next_seq(), cmd_id, payload)
        if len(self.serial_tx) + len(frame) > _MAX_SERIAL_TX:
            raise RuntimeError('sidecar serial transmit queue overflow')
        self.serial_tx.extend(frame)
        self.serial_tx_frames.append([len(frame), cmd_id])
        self.last_serial_tx = time.monotonic()
        if purpose is not None:
            self.internal_pending[cmd_id] = purpose

    def _queue_internal(self, msg_type, payload=b'', purpose='internal'):
        cmd_id = self._next_internal_cmd()
        self._queue_serial(msg_type, cmd_id, payload, purpose=purpose)
        if purpose in _RESEND_PURPOSES:
            self._track_resend(msg_type, cmd_id, payload)
        return cmd_id

    def _track_resend(self, msg_type, cmd_id, payload):
        if not self.args.half_duplex:
            return
        self.resend[cmd_id] = {
            'msg_type': msg_type, 'payload': bytes(payload),
            'due': None, 'sends': 1,
        }

    def _drop_superseded_resends(self, msg_type):
        """Drops resends by request kind, not by channel: a state change on
        one channel also drops a pending resend for another channel, which
        then simply times out."""
        if msg_type in _PASSIVE_TYPES:
            return
        for cmd_id, entry in list(self.resend.items()):
            pending = entry['msg_type']
            if msg_type in _STOP_TYPES:
                stale = True
            else:
                stale = (pending not in _PASSIVE_TYPES and
                         pending not in _STOP_TYPES)
            if stale:
                self.resend.pop(cmd_id)
                logging.info('dropped resend of 0x%02X cmd=%d: superseded by 0x%02X',
                             entry['msg_type'], cmd_id, msg_type)

    def _resend_wait(self):
        return self.args.resend_timeout * self.rng.uniform(*_RESEND_JITTER)

    def _resend_wanted(self, cmd_id):
        if cmd_id >= _INTERNAL_BASE:
            return cmd_id in self.internal_pending
        record = self.external_pending.get(cmd_id)
        return (record is not None and not record.get('orphaned') and
                record.get('kind') in ('request', 'operation', 'operation_query'))

    def _service_resends(self, now):
        """Re-send unanswered requests with the same cmd_id and a new seq;
        the firmware drops a frame whose seq does not advance."""
        for cmd_id, entry in list(self.resend.items()):
            if entry['due'] is None or now < entry['due']:
                continue
            if not self._resend_wanted(cmd_id):
                self.resend.pop(cmd_id, None)
                continue
            if entry['sends'] >= self.args.resend_attempts:
                self.resend.pop(cmd_id, None)
                logging.warning('no reply to 0x%02X cmd=%d after %d sends',
                                entry['msg_type'], cmd_id, entry['sends'])
                continue
            self._queue_serial(entry['msg_type'], cmd_id, entry['payload'],
                               resend=True)
            entry['sends'] += 1
            entry['due'] = None
            logging.info('resent 0x%02X cmd=%d attempt %d',
                         entry['msg_type'], cmd_id, entry['sends'])

    def _rx_quiet(self):
        return min(self.args.rx_quiet_ms / 1000.0, _WRITE_GATE_MAX)

    def _write_gated(self, now):
        """Half-duplex holds transmit while a frame is arriving and for a
        short quiet time after the last received byte, since the firmware
        sends replies back to back."""
        if not self.args.half_duplex:
            return False
        if now - self.last_rx_byte < self._rx_quiet():
            return True
        return (self.serial_decoder.pending and
                now - self.partial_since < _WRITE_GATE_MAX)

    def _select_timeout(self, now):
        timeout = 0.25
        if not self.args.half_duplex or self.serial is None:
            return timeout
        for entry in self.resend.values():
            if entry['due'] is not None:
                timeout = min(timeout, entry['due'] - now)
        if self.serial_tx and self._write_gated(now):
            release = self.last_rx_byte + self._rx_quiet()
            if self.serial_decoder.pending:
                release = max(release, self.partial_since + _WRITE_GATE_MAX)
            timeout = min(timeout, release - now)
        return max(0.001, timeout)

    def _queue_reliable(self, frame):
        if len(self.reliable) >= _MAX_RELIABLE:

            logging.error(
                'reliable IPC queue saturated; dropping stalled Klipper client')
            self._drop_client()
        if len(self.reliable) < _MAX_RELIABLE:
            self.reliable.append(frame)

    def _queue_client(self, op, arg1=0, arg2=0, arg3=0, payload=b'',
                      reliable=False, urgent=False, control=False):
        frame = transport.encode_message(op, arg1, arg2, arg3, payload)
        blocked = (self.client is None or
                   ((self.client_paused or
                     (self.client_control_only and not control)) and
                    not urgent))
        if reliable and blocked:
            self._queue_reliable(frame)
            return
        if blocked:
            return
        if len(self.client_tx) + len(frame) > _MAX_CLIENT_TX:
            if reliable:
                self._queue_reliable(frame)

            return
        self._append_client_frame(frame)

    def _append_client_frame(self, frame):
        if frame[4] == transport.OP_PACKET:
            frame = bytearray(frame)
            struct.pack_into('<I', frame, 9, self.client_seq)
            self.client_seq = (self.client_seq + 1) & 0xffffffff
            if self.client_seq == 0:
                self.client_seq = 1
        self.client_tx.extend(frame)

    def _queue_packet_client(self, msg_type, seq, cmd_id, payload,
                             reliable=False, urgent=False, control=False):
        if msg_type in (protocol.MSG_STATUS, protocol.MSG_SNAPSHOT):
            payload = protocol.map_status_operation_id(
                payload, self._client_operation_id)
        self._queue_client(
            transport.OP_PACKET, msg_type, 0, cmd_id, payload,
            reliable=reliable, urgent=urgent, control=control)

    def _queue_link(self, online, error=''):
        self._queue_client(
            transport.OP_LINK, 1 if online else 0,
            self.serial_generation, self.session_id,
            str(error or '').encode('utf-8', 'replace'), reliable=True,
            urgent=not bool(online), control=True)

    def _flush_reliable(self, include_status=True):
        if self.client is None or self.client_paused:
            return
        while self.reliable:
            frame = self.reliable[0]
            if len(self.client_tx) + len(frame) > _MAX_CLIENT_TX:
                break
            self._append_client_frame(frame)
            self.reliable.popleft()
        if include_status and self.latest_status is not None:
            msg_type, seq, cmd_id, payload = self.latest_status
            self._queue_packet_client(msg_type, seq, cmd_id, payload)
            self.last_status_sent = time.monotonic()

    def _accept_client(self):
        conn, _address = self.listener.accept()
        conn.setblocking(False)
        self._drop_client()
        self.client = conn
        self.client_decoder.clear()
        self.client_tx[:] = b''
        self.client_epoch += 1
        self.client_seq = 1
        self.client_paused = False
        self.client_control_only = False
        self._queue_link(self.session_ready, '' if self.session_ready else 'BMCU transport is connecting')

    def _drop_client(self):
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
        self.client = None
        self.client_decoder.clear()
        self.client_tx[:] = b''

        old_epoch = self.client_epoch
        orphaned = False
        for wire, record in list(self.external_pending.items()):
            if record.get('epoch') != old_epoch:
                continue
            if record.get('kind') == 'operation':
                record['orphaned'] = True
                orphaned = True
            else:
                self._remove_external(wire)
        if orphaned and self.serial is not None and self.session_ready:
            try:
                # Not resent: a late ABORT_OP would abort an operation the
                # next client starts after it.
                self._queue_internal(
                    protocol.MSG_ABORT_OP, b'', 'orphan_abort')
                logging.warning(
                    'aborting BMCU operation orphaned by Klipper disconnect')
            except Exception:
                logging.exception('could not abort orphaned BMCU operation')
        self.pending_local_hello[:] = [
            value for value in self.pending_local_hello
            if value[0] != old_epoch]
        self.pending_local_snapshot[:] = [
            value for value in self.pending_local_snapshot
            if value[0] != old_epoch]
        self.reliable.clear()

    @staticmethod
    def _serial_path_rank(path):
        path = str(path)
        if path.startswith('/dev/serial/by-path/'):
            return 0
        if path.startswith('/dev/serial/by-id/'):
            return 1
        if path.startswith('/dev/ttyCH343USB'):
            return 2
        if path.startswith('/dev/ttyUSB'):
            return 3
        if path.startswith('/dev/ttyACM'):
            return 4
        return 5

    def _serial_lease_name(self, resolved):
        info = os.stat(resolved)
        if not stat.S_ISCHR(info.st_mode):
            raise RuntimeError('serial candidate is not a character device')
        return os.path.join(
            os.path.dirname(self.args.status_file),
            '.serial-lease-%d-%d.lock' %
            (os.major(info.st_rdev), os.minor(info.st_rdev)))

    def _acquire_serial_lease(self, resolved):
        if self.serial_lease_fd is not None:
            raise RuntimeError('serial lease is already held')
        path = self._serial_lease_name(resolved)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, 'O_CLOEXEC'):
            flags |= os.O_CLOEXEC
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError('unsafe serial lease file')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.ftruncate(fd, 0)
            os.write(fd, ('%s %d\n' % (self.args.name, os.getpid())).encode('ascii'))
            self.serial_lease_fd = fd
            self.serial_lease_path = path
            return True
        except Exception:
            os.close(fd)
            return False

    def _release_serial_lease(self):
        fd = self.serial_lease_fd
        self.serial_lease_fd = None
        self.serial_lease_path = ''
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass

    def _serial_candidates(self):
        paths = [self.args.port]
        if self.args.expected_uid and self.args.scan_fallback:
            for pattern in ('/dev/serial/by-path/*', '/dev/serial/by-id/*',
                            '/dev/ttyCH343USB*', '/dev/ttyUSB*', '/dev/ttyACM*'):
                paths.extend(glob.glob(pattern))
        grouped = {}
        excluded_real = set()
        for excluded in self.args.exclude_ports:
            try:
                if os.path.exists(excluded):
                    excluded_real.add(os.path.realpath(excluded))
            except OSError:
                pass
        primary_real = ''
        try:
            if os.path.exists(self.args.port):
                primary_real = os.path.realpath(self.args.port)
        except OSError:
            pass
        now = time.monotonic()
        self.foreign_uid_until = {
            key: value for key, value in self.foreign_uid_until.items()
            if value > now}
        for path in paths:
            try:
                resolved = os.path.realpath(path)
                info = os.stat(resolved)
            except OSError:
                continue
            if self.foreign_uid_until.get(resolved, 0.0) > now:
                continue
            if not stat.S_ISCHR(info.st_mode):
                continue
            tty = os.path.basename(resolved)
            if path != self.args.port and not tty.startswith(('ttyUSB', 'ttyCH343USB', 'ttyACM')):
                continue
            if resolved in excluded_real:
                continue
            aliases = grouped.setdefault(resolved, set())
            aliases.add(path)
        result = []
        for resolved, aliases in grouped.items():
            preferred = min(aliases, key=lambda value: (self._serial_path_rank(value), value))
            result.append((resolved, preferred))
        result.sort(key=lambda item: (
            0 if self.last_good_port and item[1] == self.last_good_port else
            1 if primary_real and item[0] == primary_real else 2,
            self._serial_path_rank(item[1]), item[1]))
        return [item[1] for item in result]

    def _open_serial(self):
        if self.serial_released or self.serial is not None:
            return
        import serial
        candidates = self._serial_candidates()
        if not candidates:
            return
        last_error = None
        for offset in range(len(candidates)):
            index = (self.serial_candidate_cursor + offset) % len(candidates)
            port = candidates[index]
            try:
                resolved = os.path.realpath(port)
                if not self._acquire_serial_lease(resolved):
                    continue
            except OSError as exc:
                last_error = exc
                continue
            connection = serial.Serial()
            connection.port = port
            connection.baudrate = self.args.baud
            connection.timeout = 0
            connection.write_timeout = 0
            connection.rtscts = False
            connection.dsrdtr = False
            if hasattr(connection, 'exclusive'):
                try:
                    connection.exclusive = True
                except Exception:
                    pass
            connection.dtr = True
            connection.rts = False
            try:
                connection.open()
            except Exception as exc:
                last_error = exc
                try:
                    connection.close()
                except Exception:
                    pass
                self._release_serial_lease()
                continue
            self.serial_candidate_cursor = (index + 1) % len(candidates)
            try:
                connection.setDTR(True)
                connection.setRTS(False)
                attrs = termios.tcgetattr(connection.fileno())
                attrs[2] &= ~termios.HUPCL
                termios.tcsetattr(connection.fileno(), termios.TCSANOW, attrs)
            except Exception:
                pass
            try:
                os.set_blocking(connection.fileno(), False)
            except (AttributeError, OSError):
                pass
            if self.args.half_duplex:
                reason = request_low_latency(connection.fileno())
                if reason is None:
                    latency = _usb_latency_timer(port)
                    logging.info('serial low-latency on%s',
                                 ' (latency_timer %s ms)' % latency if latency else '')
                else:
                    logging.info('serial low-latency not supported: %s', reason)
            self.serial = connection
            self.current_port = port
            self.serial_decoder = protocol.StreamDecoder()
            self.serial_tx[:] = b''
            self.serial_tx_frames.clear()
            self.resend.clear()
            self.serial_generation = (self.serial_generation + 1) & 0xffffffff
            self.seq = 1
            self.internal_pending.clear()
            self.session_id = 0
            self.session_ready = False
            self.hello_sent = False
            self.handshake_phase = 'idle'
            self.heartbeat_cmd = 0
            self.heartbeat_sent_at = 0.0
            now = time.monotonic()
            self.last_serial_rx = now
            self.last_serial_tx = now
            self.serial_settle_until = now + self.args.connect_settle
            self.handshake_started_at = self.serial_settle_until
            self.next_handshake_action = self.serial_settle_until
            logging.info('opened %s for %s', port, self.args.name)
            self._write_status_file(force=True)
            return
        if last_error is not None:
            raise RuntimeError('no serial candidate could be opened: %s' % last_error)

    def _close_serial(self, reason, notify=True):
        was_open = self.serial is not None or self.session_ready
        if self.serial is not None:
            try:
                self.serial.close()
            except Exception:
                pass
        self.serial = None
        self._release_serial_lease()
        self.current_port = ''
        self.serial_tx[:] = b''
        self.serial_tx_frames.clear()
        self.serial_decoder = protocol.StreamDecoder()
        self.resend.clear()
        self.internal_pending.clear()
        self.external_pending.clear()
        self.operation_wire_by_client.clear()
        self.reliable.clear()
        self.session_ready = False
        self.hello_sent = False
        self.handshake_phase = 'idle'
        self.handshake_started_at = 0.0
        self.next_handshake_action = 0.0
        self.heartbeat_cmd = 0
        self.heartbeat_sent_at = 0.0
        self.session_id = 0
        self.runtime_uid = ''
        self.latest_hello = None
        self.latest_status = None
        self.latest_snapshot = None
        self.latest_caps = None
        self.pending_local_hello[:] = []
        self.pending_local_snapshot[:] = []
        if not self.serial_released:
            self.next_serial_connect = time.monotonic() + self.args.reconnect
        self.latest_status_dict = None
        self.last_semantic_status = None
        self._write_status_file(force=True)
        if notify and was_open:
            logging.warning('serial offline: %s', reason)
            self._queue_link(False, reason)

    def _start_handshake(self):
        for cmd_id, purpose in list(self.internal_pending.items()):
            if purpose in ('hello', 'confirm'):
                self.internal_pending.pop(cmd_id, None)
        nonce = struct.unpack('<I', os.urandom(4))[0]
        self._queue_internal(
            protocol.MSG_HELLO, struct.pack('<I', nonce), 'hello')
        self.hello_sent = True
        self.handshake_phase = 'wait_hello'
        self.next_handshake_action = time.monotonic() + 0.60

    def _finish_ready(self):
        self.session_ready = True
        self.handshake_phase = 'ready'
        self.handshake_started_at = 0.0
        self.next_handshake_action = 0.0
        if self.current_port:
            self.last_good_port = self.current_port
        self.heartbeat_cmd = 0
        self.heartbeat_sent_at = 0.0
        self._queue_internal(protocol.MSG_UPDATE_CANCEL, b'', 'resume_update')
        self._queue_internal(protocol.MSG_GET_SNAPSHOT, b'', 'snapshot')
        self._queue_link(True)
        self._write_status_file(force=True)
        pending = list(self.pending_local_hello)
        self.pending_local_hello[:] = []
        for epoch, cmd_id in pending:
            if epoch == self.client_epoch:
                self._synthetic_hello(cmd_id)

    def _queue_pending_hello(self, cmd_id):
        self.pending_local_hello[:] = [
            item for item in self.pending_local_hello
            if item[0] != self.client_epoch]
        self.pending_local_hello.append((self.client_epoch, cmd_id))
        if len(self.pending_local_hello) > 128:
            del self.pending_local_hello[:-128]

    def _synthetic_hello(self, cmd_id):
        if self.latest_hello is None:
            self._queue_pending_hello(cmd_id)
            return
        self._queue_packet_client(
            protocol.MSG_HELLO_ACK, 0, cmd_id, self.latest_hello,
            reliable=True, control=True)

    def _synthetic_ack(self, cmd_id, ok=True, error=0):
        payload = struct.pack('<IBH', cmd_id, 1 if ok else 0, int(error))
        self._queue_packet_client(
            protocol.MSG_ACK, 0, cmd_id, payload, reliable=True, control=True)

    def _queue_pending_snapshot(self, cmd_id):
        self.pending_local_snapshot[:] = [
            value for value in self.pending_local_snapshot
            if value[0] != self.client_epoch]
        self.pending_local_snapshot.append((self.client_epoch, cmd_id))

    def _handle_client_message(self, message):
        op, arg1, arg2, _arg3, payload = message
        if op != transport.OP_SEND:
            return
        msg_type = int(arg1) & 0xff
        cmd_id = int(arg2) & 0xffffffff
        if msg_type == protocol.MSG_HELLO:
            if self.session_ready and self.latest_hello is not None:
                self._synthetic_hello(cmd_id)
            else:
                self._queue_pending_hello(cmd_id)
            return
        if msg_type == protocol.MSG_SESSION_CONFIRM:
            valid = (self.session_ready and len(payload) == 4 and
                     struct.unpack('<I', payload)[0] == self.session_id)
            self._synthetic_ack(cmd_id, valid, 0 if valid else 1)
            return

        if self.serial is None or not self.session_ready:
            self._queue_client(
                transport.OP_ERROR, cmd_id, 0, 0,
                b'BMCU transport is offline', reliable=True, control=True)
            return
        if msg_type == protocol.MSG_GET_SNAPSHOT:
            self._queue_pending_snapshot(cmd_id)
            if 'snapshot' not in self.internal_pending.values():
                self._queue_internal(
                    protocol.MSG_GET_SNAPSHOT, b'', 'snapshot')
            return
        if len(self.external_pending) >= _MAX_EXTERNAL_PENDING:
            self._queue_client(
                transport.OP_ERROR, cmd_id, 0, 0,
                b'BMCU sidecar command map is full',
                reliable=True, control=True)
            return

        if msg_type == protocol.MSG_GET_OP_RESULT and len(payload) == 4:
            client_op = struct.unpack('<I', payload)[0]
            target_wire = self.operation_wire_by_client.get(
                (self.client_epoch, client_op))
            completed = self.external_pending.get(target_wire)
            if client_op and not target_wire:
                self._queue_packet_client(
                    protocol.MSG_ERROR, 0, cmd_id,
                    struct.pack('<BHI', 0xff, 22, client_op),
                    reliable=True, control=True)
                return
            if (completed is not None and
                    completed.get('kind') == 'operation_complete' and
                    completed.get('result_payload') is not None):
                self._queue_packet_client(
                    protocol.MSG_OP_RESULT, 0, cmd_id,
                    completed.get('result_payload'), reliable=True,
                    urgent=True, control=True)
                return

        wire_cmd = self._next_external_cmd()
        record = {
            'epoch': self.client_epoch,
            'client_cmd': cmd_id,
            'deadline': time.monotonic() + _EXTERNAL_TIMEOUT,
            'kind': 'request',
            'msg_type': msg_type,
        }
        if msg_type in _OPERATION_START_TYPES:
            record['kind'] = 'operation'
            self.operation_wire_by_client[(self.client_epoch, cmd_id)] = wire_cmd
            logging.info('operation map start client=%d wire=%d type=0x%02X',
                         cmd_id, wire_cmd, msg_type)
        elif msg_type == protocol.MSG_GET_OP_RESULT and len(payload) == 4:
            client_op = struct.unpack('<I', payload)[0]
            target_wire = self.operation_wire_by_client.get(
                (self.client_epoch, client_op))
            record['kind'] = 'operation_query'
            record['target_client_op'] = client_op
            record['target_wire_op'] = target_wire or 0
            if target_wire:
                payload = struct.pack('<I', target_wire)
        self.external_pending[wire_cmd] = record
        self._queue_serial(msg_type, wire_cmd, payload)
        if msg_type not in _NO_RESEND_TYPES:
            self._track_resend(msg_type, wire_cmd, payload)

    def _handle_control(self, data):
        if not data:
            return
        command = data[:1]
        if command == transport.CTRL_PAUSE:
            self.client_paused = True
            self.client_control_only = False
            return
        if command == transport.CTRL_RESUME_REQUIRED:

            self.client_paused = False
            self.client_control_only = True
            self._queue_link(
                self.session_ready, '' if self.session_ready else
                'BMCU transport is connecting')
            self._flush_reliable(include_status=False)
            return
        if command == transport.CTRL_RESUME:
            self.client_paused = False
            self.client_control_only = False
            self._queue_link(self.session_ready, '' if self.session_ready else 'BMCU transport is connecting')
            self._flush_reliable()
            return
        if command == transport.CTRL_RELEASE_SERIAL:
            self.serial_released = True
            self._close_serial('released for firmware update')
            return
        if command == transport.CTRL_RECONNECT_SERIAL:
            self.serial_released = False
            self.next_serial_connect = time.monotonic()
            return
        if command == transport.CTRL_SNAPSHOT and self.session_ready and self.serial is not None:
            self._queue_internal(protocol.MSG_GET_SNAPSHOT, b'', 'snapshot')

    def _awaiting_reply(self, cmd_id):
        return cmd_id in self.internal_pending or cmd_id in self.external_pending

    def _handle_serial_packet(self, msg_type, seq, cmd_id, payload):
        now = time.monotonic()
        self.last_serial_rx = now
        if msg_type & 0x80:
            self.resend.pop(cmd_id, None)
        if not cmd_id and msg_type in _FIRMWARE_STOP_EVENTS and self.resend:
            self._drop_superseded_resends(msg_type)
        if not (self.args.half_duplex and msg_type & 0x80 and cmd_id):
            self._dispatch_serial_packet(msg_type, seq, cmd_id, payload)
            return
        if self.answered.get(cmd_id, 0.0) > now:
            logging.info('dropped duplicate reply 0x%02X cmd=%d', msg_type, cmd_id)
            return
        # A request whose record a reply retired is answered; an operation
        # keeps its record until it completes and dedupes its own replies.
        awaiting = self._awaiting_reply(cmd_id)
        self._dispatch_serial_packet(msg_type, seq, cmd_id, payload)
        if awaiting and not self._awaiting_reply(cmd_id):
            if len(self.answered) >= _MAX_ANSWERED:
                self._expire_answered(float('inf'))
            self.answered[cmd_id] = now + _ANSWERED_TTL

    def _expire_answered(self, now):
        for cmd_id, expiry in list(self.answered.items()):
            if expiry <= now:
                del self.answered[cmd_id]

    def _dispatch_serial_packet(self, msg_type, seq, cmd_id, payload):
        purpose = self.internal_pending.get(cmd_id)
        if purpose == 'hello' and msg_type == protocol.MSG_HELLO_ACK:
            hello = protocol.parse_hello(payload)
            if self.args.expected_uid and hello['uid'] != self.args.expected_uid:
                try:
                    if self.current_port:
                        self.foreign_uid_until[os.path.realpath(self.current_port)] = time.monotonic() + 5.0
                except OSError:
                    pass
                raise RuntimeError('UID mismatch expected=%s got=%s' %
                                   (self.args.expected_uid, hello['uid']))
            self.latest_hello = payload
            self.runtime_uid = hello['uid']
            self.session_id = int(hello['session_id'])
            self.internal_pending.pop(cmd_id, None)
            for pending_cmd, pending_purpose in list(self.internal_pending.items()):
                if pending_purpose == 'hello':
                    self.internal_pending.pop(pending_cmd, None)
            confirm = struct.pack('<I', self.session_id)
            self._queue_internal(protocol.MSG_SESSION_CONFIRM, confirm, 'confirm')
            self.handshake_phase = 'wait_confirm'
            self.next_handshake_action = time.monotonic() + 1.0
            return
        if purpose == 'confirm' and msg_type == protocol.MSG_ACK:
            echo, ok, error = struct.unpack('<IBH', payload)
            if echo != cmd_id or not ok:
                raise RuntimeError('session confirmation failed error=%d' % error)
            self.internal_pending.pop(cmd_id, None)
            self._finish_ready()
            return
        if purpose == 'heartbeat' and msg_type == protocol.MSG_PONG:
            self.internal_pending.pop(cmd_id, None)
            self.heartbeat_cmd = 0
            self.heartbeat_sent_at = 0.0
            return
        if purpose == 'orphan_abort' and msg_type in (
                protocol.MSG_ACK, protocol.MSG_ERROR):
            self.internal_pending.pop(cmd_id, None)
            return
        if purpose == 'resume_update' and msg_type in (
                protocol.MSG_ACK, protocol.MSG_ERROR):
            if msg_type != protocol.MSG_ACK or len(payload) != 7:
                raise RuntimeError('could not leave firmware-update mode after reconnect')
            echo, ok, error = struct.unpack('<IBH', payload)
            if echo != cmd_id or not ok:
                raise RuntimeError('firmware-update cancellation failed error=%d' % error)
            self.internal_pending.pop(cmd_id, None)
            return
        if purpose == 'snapshot' and msg_type == protocol.MSG_SNAPSHOT:
            self.internal_pending.pop(cmd_id, None)
            self.latest_snapshot = payload
            try:
                self.latest_status_dict = protocol.parse_snapshot(payload)['status']
                self.last_semantic_status = self._semantic_status_fingerprint(
                    self.latest_status_dict)
                self._write_status_file(force=True)
            except Exception:
                logging.exception('invalid snapshot while publishing sidecar state')
            pending = list(self.pending_local_snapshot)
            self.pending_local_snapshot[:] = []
            for epoch, external_cmd in pending:
                if epoch == self.client_epoch:
                    self._queue_packet_client(
                        protocol.MSG_SNAPSHOT, seq, external_cmd, payload,
                        reliable=True, control=True)
            return
        if purpose == 'caps' and msg_type == protocol.MSG_CAPS:
            self.internal_pending.pop(cmd_id, None)
            self.latest_caps = payload
            return

        if msg_type == protocol.MSG_STATUS:
            self.latest_status = (msg_type, seq, 0, payload)
            now = time.monotonic()
            semantic_changed = False
            try:
                self.latest_status_dict = protocol.parse_status(payload)
                fingerprint = self._semantic_status_fingerprint(
                    self.latest_status_dict)
                semantic_changed = fingerprint != self.last_semantic_status
                self.last_semantic_status = fingerprint

                self._write_status_file(force=semantic_changed)
            except Exception:
                logging.exception('invalid status while publishing sidecar state')
            record = self.external_pending.get(cmd_id)
            if record is not None and record.get('kind') == 'request':
                self._remove_external(cmd_id)
                if record.get('epoch') == self.client_epoch:
                    self._queue_packet_client(
                        msg_type, seq, record.get('client_cmd'), payload,
                        reliable=True, control=True)
                    self.last_status_sent = now
            elif semantic_changed:

                self._queue_packet_client(
                    msg_type, seq, 0, payload, reliable=True,
                    urgent=True, control=True)
                self.last_status_sent = now
            elif (not self.client_paused and not self.client_control_only and
                  now - self.last_status_sent >= self.args.status_interval):
                self._queue_packet_client(msg_type, seq, 0, payload)
                self.last_status_sent = now
            return

        record = self.external_pending.get(cmd_id)
        if msg_type == protocol.MSG_OP_RESULT:
            if record is not None and record.get('kind') in (
                    'operation', 'operation_complete'):
                client_op = record.get('client_cmd')
                translated = self._rewrite_op_result_id(payload, client_op)

                first_result = record.get('kind') == 'operation'
                record['kind'] = 'operation_complete'
                record['deadline'] = time.monotonic() + _COMPLETED_OPERATION_TTL
                record['result_payload'] = translated
                if first_result and record.get('epoch') == self.client_epoch:
                    self._queue_packet_client(
                        msg_type, seq, client_op, translated,
                        reliable=True, urgent=True, control=True)
                if first_result:
                    logging.info('operation map finish client=%d wire=%d',
                                 client_op, cmd_id)
                if record.get('orphaned'):
                    self._remove_external(cmd_id)
                return
            if record is not None and record.get('kind') == 'operation_query':
                wire_op = struct.unpack_from('<I', payload)[0]
                client_op = self._client_operation_id(wire_op)
                target_wire = record.get('target_wire_op', 0)
                if target_wire and wire_op != target_wire:
                    raise RuntimeError('operation result ID does not match query')
                translated = self._rewrite_op_result_id(payload, client_op)
                self._remove_external(cmd_id)
                if record.get('epoch') == self.client_epoch:
                    self._queue_packet_client(
                        msg_type, seq, record.get('client_cmd'), translated,
                        reliable=True, urgent=True, control=True)
                return

        if record is not None:
            kind = record.get('kind')

            if kind in ('operation', 'operation_complete') and msg_type == protocol.MSG_ACK:
                ok = 1
                if len(payload) == 7:
                    _wire_echo, ok, error = struct.unpack('<IBH', payload)
                    payload = struct.pack(
                        '<IBH', record.get('client_cmd'), ok, error)

                # A resend can draw a second ACK for the same operation.
                duplicate = self.args.half_duplex and record.get('acked')
                record['acked'] = True
                if (kind == 'operation' and not duplicate and
                        record.get('epoch') == self.client_epoch):
                    self._queue_packet_client(
                        msg_type, seq, record.get('client_cmd'), payload,
                        reliable=True, control=True)

                if not ok and kind == 'operation':
                    self._remove_external(cmd_id)
                return
            self._remove_external(cmd_id)
            if record.get('epoch') == self.client_epoch:
                if msg_type == protocol.MSG_ACK and len(payload) == 7:
                    _wire_echo, ok, error = struct.unpack('<IBH', payload)
                    payload = struct.pack(
                        '<IBH', record.get('client_cmd'), ok, error)
                self._queue_packet_client(
                    msg_type, seq, record.get('client_cmd'), payload,
                    reliable=True, control=True)
            return

        if msg_type in (protocol.MSG_JAM, protocol.MSG_ERROR,
                        protocol.MSG_OP_RESULT):
            if msg_type == protocol.MSG_OP_RESULT:
                wire_op = struct.unpack_from('<I', payload)[0]
                payload = self._rewrite_op_result_id(
                    payload, self._client_operation_id(wire_op))
            self._queue_packet_client(
                msg_type, seq, 0, payload, reliable=True,
                urgent=True, control=True)

    def _read_serial(self):
        data = os.read(self.serial.fileno(), 4096)
        if not data:
            raise OSError(errno.EIO, 'serial EOF')
        self.last_rx_byte = time.monotonic()
        previous = self.serial_decoder.errors
        was_pending = self.serial_decoder.pending
        packets = self.serial_decoder.feed(data)
        # A frame that ended (decoded or discarded) means any partial frame
        # now pending is a new one.
        if self.serial_decoder.pending and (
                packets or not was_pending or
                self.serial_decoder.errors != previous):
            self.partial_since = self.last_rx_byte
        if self.serial_decoder.incompatible_version is not None:
            raise RuntimeError('incompatible BMCU protocol version')
        if self.serial_decoder.errors != previous:
            logging.warning('discarded %d malformed serial frame(s)',
                            self.serial_decoder.errors - previous)
        for packet in packets:
            self._handle_serial_packet(*packet)

    def _read_client(self):
        data = self.client.recv(65536)
        if not data:
            self._drop_client()
            return
        for message in self.client_decoder.feed(data):
            self._handle_client_message(message)

    def _flush_serial(self):
        if not self.serial_tx:
            return
        limit = 4096
        # Half-duplex writes one frame per pass so the write gate is checked
        # again before each frame.
        if self.args.half_duplex and self.serial_tx_frames:
            limit = self.serial_tx_frames[0][0]
        try:
            written = os.write(self.serial.fileno(), self.serial_tx[:limit])
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return
            raise
        if written:
            del self.serial_tx[:written]
            self._consume_tx_frames(written)

    def _consume_tx_frames(self, written):
        while written and self.serial_tx_frames:
            head = self.serial_tx_frames[0]
            taken = min(written, head[0])
            head[0] -= taken
            written -= taken
            if not head[0]:
                self.serial_tx_frames.popleft()
                self._frame_written(head[1])

    def _frame_written(self, cmd_id):
        """Start a resend timer once its frame is on the wire, not when it
        was queued behind a held write."""
        entry = self.resend.get(cmd_id)
        if entry is not None and entry['due'] is None:
            entry['due'] = time.monotonic() + self._resend_wait()

    def _flush_client(self):
        if self.client is None or not self.client_tx:
            return
        try:
            written = self.client.send(self.client_tx[:65536])
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return
            raise
        if written:
            del self.client_tx[:written]
            self._flush_reliable(include_status=False)

    def _periodic(self, now):
        if self.serial is None and not self.serial_released and now >= self.next_serial_connect:
            self.next_serial_connect = now + self.args.reconnect
            try:
                self._open_serial()
                self.last_connect_error = ''
            except Exception as exc:
                error = str(exc)
                if error != self.last_connect_error:
                    logging.warning('serial connect failed: %s', error)
                self.last_connect_error = error
        if self.serial is not None:
            if not self.session_ready:
                if (now >= self.serial_settle_until and
                        self.handshake_started_at and
                        now - self.handshake_started_at >= self.args.connection_timeout):
                    self._close_serial('HELLO/session handshake timeout')
                elif now >= self.next_handshake_action:
                    try:
                        self._start_handshake()
                    except Exception as exc:
                        self._close_serial(str(exc))
            if self.session_ready:
                heartbeat_retry = max(1.0, min(
                    self.args.heartbeat * 0.5,
                    self.args.connection_timeout * 0.25))
                if (self.heartbeat_cmd and self.heartbeat_sent_at and
                        now - self.heartbeat_sent_at >= heartbeat_retry):
                    self.internal_pending.pop(self.heartbeat_cmd, None)
                    self.heartbeat_cmd = 0
                    self.heartbeat_sent_at = 0.0

                if (now - self.last_serial_tx >= self.args.heartbeat and
                        not self.heartbeat_cmd):
                    try:
                        self.heartbeat_cmd = self._queue_internal(
                            protocol.MSG_PING, b'B', 'heartbeat')
                        self.heartbeat_sent_at = now
                    except Exception as exc:
                        self._close_serial(str(exc))
                if now - self.last_serial_rx > self.args.connection_timeout:
                    self._close_serial('receive timeout after heartbeat retries')
            if self.serial is not None and self.resend:
                try:
                    self._service_resends(now)
                except Exception as exc:
                    self._close_serial(str(exc))
        if self.answered:
            self._expire_answered(now)
        if self.external_pending:
            expired = [wire for wire, value in self.external_pending.items()
                       if value.get('deadline', 0.0) <= now]
            for wire in expired:
                record = self._remove_external(wire)
                if record and record.get('kind') == 'operation':
                    logging.error('operation map expired client=%s wire=%s',
                                  record.get('client_cmd'), wire)
        if self.client is not None and not self.client_paused:

            keepalive_interval = 10.0 if self.client_control_only else 2.0
            if now - self.last_keepalive >= keepalive_interval:
                self._queue_client(
                    transport.OP_KEEPALIVE, 0, self.serial_generation,
                    self.session_id, control=True)
                self.last_keepalive = now

    def run(self):
        try:
            self.setup()
            while self.running:
                now = time.monotonic()
                self._periodic(now)
                reads = [self.listener, self.control]
                writes = []
                if self.client is not None:
                    reads.append(self.client)
                    if self.client_tx:
                        writes.append(self.client)
                if self.serial is not None:
                    reads.append(self.serial.fileno())
                    if self.serial_tx and not self._write_gated(now):
                        writes.append(self.serial.fileno())
                try:
                    readable, writable, _errors = select.select(
                        reads, writes, [], self._select_timeout(now))
                except InterruptedError:
                    continue
                for item in readable:
                    try:
                        if item is self.listener:
                            self._accept_client()
                        elif item is self.control:
                            data, address = self.control.recvfrom(64)
                            self._handle_control(data)
                            if address:
                                reply = self._transport_status()
                                reply.pop('status', None)
                                reply['control'] = data[:1].decode('ascii')
                                self.control.sendto(json.dumps(
                                    reply, separators=(',', ':')).encode('utf-8'), address)
                        elif item is self.client:
                            self._read_client()
                        else:
                            self._read_serial()
                    except Exception as exc:
                        if item is self.client:
                            logging.warning('client disconnected: %s', exc)
                            self._drop_client()
                        elif item is self.listener or item is self.control:
                            logging.exception('local IPC failure')
                        else:
                            self._close_serial(str(exc))
                for item in writable:
                    try:
                        if item is self.client:
                            self._flush_client()
                        else:
                            self._flush_serial()
                    except Exception as exc:
                        if item is self.client:
                            logging.warning('client transmit failed: %s', exc)
                            self._drop_client()
                        else:
                            self._close_serial(str(exc))
        finally:
            self.cleanup()

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', required=True)
    parser.add_argument('--port', required=True)
    parser.add_argument('--expected-uid', default='')
    parser.add_argument('--scan-fallback', action='store_true')
    parser.add_argument('--exclude-port', action='append', default=[])
    parser.add_argument('--socket', required=True)
    parser.add_argument('--baud', type=int, default=115200)
    parser.add_argument('--heartbeat', type=float, default=5.0)
    parser.add_argument('--connection-timeout', type=float, default=15.0)
    parser.add_argument('--reconnect', type=float, default=1.0)
    parser.add_argument('--status-interval', type=float, default=0.5)
    parser.add_argument('--connect-settle', type=float, default=1.5)
    parser.add_argument('--log-file', required=True)
    parser.add_argument('--status-file', required=True)
    parser.add_argument('--settings-digest', default='')
    parser.add_argument('--half-duplex', action='store_true')
    parser.add_argument('--resend-timeout', type=float, default=0.25)
    parser.add_argument('--resend-attempts', type=int, default=3)
    parser.add_argument('--rx-quiet-ms', type=float, default=2.0)
    args = parser.parse_args()
    args.expected_uid = str(args.expected_uid or '').strip().upper()
    args.exclude_ports = tuple(str(value) for value in (args.exclude_port or []) if value)
    if args.expected_uid and (len(args.expected_uid) != 24 or
                              any(ch not in '0123456789ABCDEF' for ch in args.expected_uid)):
        parser.error('--expected-uid must be 24 hexadecimal characters')
    return args

def main():
    args = parse_args()
    handler = logging.handlers.RotatingFileHandler(
        args.log_file, maxBytes=1024 * 1024, backupCount=1)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s %(message)s'))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)

    state = {'running': True, 'daemon': None}

    def stop(_signum, _frame):
        state['running'] = False
        daemon = state.get('daemon')
        if daemon is not None:
            daemon.running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    descriptor = os.open(args.socket + '.lock',
                         os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'r+') as lifetime_lock:
        if not stat.S_ISREG(os.fstat(lifetime_lock.fileno()).st_mode):
            raise RuntimeError('BMCU transport lock is not a regular file')
        try:
            fcntl.flock(lifetime_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('another BMCU transport already owns this socket')
        os.fchmod(lifetime_lock.fileno(), 0o600)
        args.lifetime_lock = lifetime_lock
        args.process_record = {
            'pid': os.getpid(), 'daemon': os.path.realpath(__file__),
            'name': args.name, 'socket': args.socket, 'port': args.port,
            'uid': args.expected_uid, 'status_file': args.status_file,
            'settings_digest': args.settings_digest,
        }
        while state['running']:
            args.process_record['ready'] = False
            lifetime_lock.seek(0)
            json.dump(args.process_record, lifetime_lock, sort_keys=True)
            lifetime_lock.truncate()
            lifetime_lock.flush()
            daemon = TransportDaemon(args)
            state['daemon'] = daemon
            try:
                daemon.run()
            except Exception:
                logging.exception('BMCU transport cycle failed; rebuilding sidecar')
                if state['running']:
                    time.sleep(min(1.0, max(0.1, args.reconnect)))
            finally:
                state['daemon'] = None

if __name__ == '__main__':
    main()
