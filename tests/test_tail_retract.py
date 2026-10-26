# SPDX-License-Identifier: GPL-3.0-or-later

"""TAIL_RETRACT end to end: BMCUDevice requests against the simulator.

The device's sidecar transport is replaced by a direct link: send() hands the
frame to the simulator's handle_packet(), and the reactor's pause() reads the
simulator's replies off the pty and feeds them to the device's packet handler.
"""

import math
import os
import re
import select
import struct
import time

import pytest

from bmcu_core import protocol
from bmcu_core.device import BMCUDevice

from bmcu_sim import BmcuSim

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
FIRMWARE_SRC = os.path.join(ROOT, 'firmware', 'src')


class Reactor(object):
    NEVER = 9999999999999999.

    def __init__(self):
        self.link = None

    def monotonic(self):
        return time.monotonic()

    def register_timer(self, callback, waketime):
        return object()

    def update_timer(self, timer, waketime):
        pass

    def pause(self, waketime):
        self.link.pump(waketime)


class Manager(object):
    def __init__(self, reactor):
        self.printer = None
        self.reactor = reactor
        self.baud = 115200
        self.transport_socket_dir = '/nonexistent'
        self.reconnect_interval = 1.0
        self.tx_queue_limit = 65536
        self._required_transport_users = 0


class LinkedDevice(BMCUDevice):
    def __init__(self, sim):
        reactor = Reactor()
        super(LinkedDevice, self).__init__(Manager(reactor), 'sim', sim.port)
        reactor.link = self
        self.sim = sim
        self.sent = []
        self.wire_decoder = protocol.StreamDecoder()
        self.hello_validated = True
        self.firmware_compatible = True
        self.ipc_connected = True
        self.connected = True
        self.caps = {'session_id': sim.session_id}
        with sim.lock:
            sim.host_session_ready = True
            sim.seq_rx_last = 0

    def send(self, msg_type, payload=b'', cmd_id=None):
        if cmd_id is None:
            cmd_id = self._next_cmd_id()
        self.sent.append((msg_type, cmd_id, bytes(payload)))
        self.sim.handle_packet(msg_type, self._next_seq(), cmd_id, payload)
        return cmd_id

    def _send_sidecar_control(self, command):
        pass

    def _schedule_manager_work(self, eventtime=None, delay=None, force=False):
        pass

    def pump(self, waketime):
        fd = self.sim._slave_fd
        while True:
            remaining = waketime - time.monotonic()
            readable, _w, _x = select.select([fd], [], [], max(0.0, remaining))
            if fd in readable:
                for packet in self.wire_decoder.feed(os.read(fd, 4096)):
                    self._handle_packet(*packet)
                return
            if remaining <= 0.0:
                return


@pytest.fixture
def sim():
    value = BmcuSim()
    yield value
    value.close()


@pytest.fixture
def device(sim):
    return LinkedDevice(sim)


def raw_tail_retract(sim, seq, cmd_id, channel, millimeters, timeout_ms=20000):
    with sim.lock:
        sim.host_session_ready = True
    sim.handle_packet(protocol.MSG_TAIL_RETRACT, seq, cmd_id,
                      struct.pack('<BfI', channel, millimeters, timeout_ms))


def sent_errors(sim, cmd_id):
    return [struct.unpack('<BHI', frame.payload)[1]
            for frame in sim.frames('tx', protocol.MSG_ERROR)
            if frame.cmd_id == cmd_id]


def test_tail_retract_runs_with_inlet_empty(sim, device):
    sim.present[1] = 0
    sim.route[1] = protocol.ROUTE_LOADED
    op_id = device.start_tail_retract(1, 300.0, 20000)
    result = device.wait_for_op(op_id, timeout=5.0)
    assert result['type'] == protocol.OP_TAIL_RETRACT
    assert (result['state'], result['reason']) == (protocol.OP_STATE_DONE, 'target')
    assert sim.meters[1] == pytest.approx(-0.300, abs=0.001)
    assert result['measured_mm'] == pytest.approx(300.0, abs=1.0)
    assert sim.route[1] == protocol.ROUTE_EMPTY
    assert sim.motion[1] == protocol.MOTION_IDLE
    assert device.sent[0] == (protocol.MSG_TAIL_RETRACT, op_id,
                              struct.pack('<BfI', 1, 300.0, 20000))


@pytest.mark.parametrize('millimeters', [4.0, 4.99, 2000.5, math.nan, math.inf])
def test_tail_retract_host_rejects_distance(device, millimeters):
    with pytest.raises(ValueError):
        device.start_tail_retract(0, millimeters, 20000)
    assert device.sent == []


@pytest.mark.parametrize('channel, millimeters', [
    (0, 4.0), (0, 2000.5), (0, math.nan), (0, math.inf), (4, 300.0)])
def test_tail_retract_rejects_short_distance(sim, channel, millimeters):
    raw_tail_retract(sim, 1, 70, channel, millimeters)
    assert sim.wait_for(lambda: sent_errors(sim, 70)) == [31]
    assert sim.operations_started == []
    assert sim.meters == [0.0] * 4


def test_tail_retract_accepts_distance_bounds(sim):
    raw_tail_retract(sim, 1, 71, 0, 5.0)
    assert sim.wait_for(lambda: sim.operations[71]['result'] is not None)
    raw_tail_retract(sim, 2, 72, 1, 2000.0)
    assert sim.operations_started == [71, 72]


def test_tail_retract_uncalibrated(sim, device):
    sim.calibrated[2] = False
    op_id = device.start_tail_retract(2, 300.0, 20000)
    result = device.wait_for_op(op_id, timeout=2.0)
    assert (result['state'], result['reason']) == (protocol.OP_STATE_FAILED,
                                                   'not_calibrated')
    time.sleep(0.1)
    assert sim.meters[2] == 0.0
    assert sim.motion[2] == protocol.MOTION_IDLE


def test_tail_retract_refused_while_channel_moving(sim, device):
    sim.motion[0] = protocol.MOTION_ON_USE
    op_id = device.start_tail_retract(0, 300.0, 20000)
    result = device.wait_for_op(op_id, timeout=2.0)
    assert (result['state'], result['reason']) == (protocol.OP_STATE_FAILED, 'busy')
    assert sim.meters[0] == 0.0


def test_tail_retract_stop_all_aborts(sim, device):
    sim.pull_speed_mms = 50.0
    op_id = device.start_tail_retract(3, 300.0, 20000)
    assert sim.wait_for(lambda: sim.meters[3] < -0.005)
    device.stop_all()
    result = device.wait_for_op(op_id, timeout=2.0)
    assert (result['state'], result['reason']) == (protocol.OP_STATE_ABORTED, 'aborted')
    assert sim.motion == [protocol.MOTION_IDLE] * 4
    stopped_at = sim.meters[3]
    time.sleep(0.1)
    assert sim.meters[3] == stopped_at > -0.300


def test_tail_retract_abort_op_aborts(sim, device):
    sim.pull_speed_mms = 50.0
    op_id = device.start_tail_retract(0, 300.0, 20000)
    assert sim.wait_for(lambda: sim.meters[0] < -0.005)
    device.abort_operation()
    result = device.wait_for_op(op_id, timeout=2.0)
    assert (result['state'], result['reason']) == (protocol.OP_STATE_ABORTED, 'aborted')
    assert sim.motion[0] == protocol.MOTION_IDLE


def test_tail_retract_timeout_fails(sim, device):
    sim.pull_speed_mms = 50.0
    op_id = device.start_tail_retract(1, 300.0, 300)
    result = device.wait_for_op(op_id, timeout=3.0)
    assert (result['state'], result['reason']) == (protocol.OP_STATE_FAILED, 'timeout')
    assert -0.300 < sim.meters[1] < 0.0
    assert sim.route[1] == protocol.ROUTE_EMPTY


def test_tail_retract_buffer_limit_fails(sim, device):
    sim.pull_speed_mms = 50.0
    op_id = device.start_tail_retract(1, 300.0, 20000)
    assert sim.wait_for(lambda: sim.meters[1] < -0.005)
    sim.buffer_pct[1] = 3
    result = device.wait_for_op(op_id, timeout=2.0)
    assert (result['state'], result['reason']) == (protocol.OP_STATE_FAILED,
                                                   'buffer_limit')


def test_tail_retract_replays_op_id(sim, device):
    op_id = device.start_tail_retract(1, 300.0, 20000)
    first = device.wait_for_op(op_id, timeout=5.0)
    moved = sim.meters[1]
    device.last_op = None
    pending = device._new_pending(op_id, (protocol.MSG_OP_RESULT,),
                                  time.monotonic() + 2.0)
    device.pending[op_id] = pending
    device.send(protocol.MSG_TAIL_RETRACT,
                protocol.pack_tail_retract(1, 300.0, 20000), op_id)
    replay = device._wait_pending(pending, 'replay timeout')
    assert replay == first
    assert sim.operations_started == [op_id]
    time.sleep(0.1)
    assert sim.meters[1] == moved


def _firmware_text(name):
    with open(os.path.join(FIRMWARE_SRC, name)) as handle:
        return handle.read()


def test_caps_advertise_tail_retract():
    header = _firmware_text('bmcu_protocol.h')
    source = _firmware_text('bmcu_protocol.cpp')
    bit = re.search(r'#define\s+BMCU_CAP_TAIL_RETRACT\s+\(1u\s*<<\s*(\d+)\)', header)
    assert bit and (1 << int(bit.group(1))) == protocol.CAP_TAIL_RETRACT == 1 << 25
    message = re.search(r'#define\s+MSG_TAIL_RETRACT\s+0x([0-9A-Fa-f]+)u', header)
    assert message and int(message.group(1), 16) == protocol.MSG_TAIL_RETRACT == 0x25
    op_type = re.search(r'OP_TAIL_RETRACT\s*=\s*(\d+)', source)
    assert op_type and int(op_type.group(1)) == protocol.OP_TAIL_RETRACT == 7
    caps = re.search(r'kCapabilities\s*=([^;]*);', source)
    assert caps and 'BMCU_CAP_TAIL_RETRACT' in caps.group(1)
