# SPDX-License-Identifier: GPL-3.0-or-later

import bmcu_host_bootstrap


def test_transport_config_half_duplex(tmp_path):
    path = tmp_path / 'bmcu.cfg'
    path.write_text('[bmcu]\n')
    assert bmcu_host_bootstrap._transport_config(str(path))['half_duplex'] is False
    path.write_text('[bmcu]\nhalf_duplex: True\n')
    assert bmcu_host_bootstrap._transport_config(str(path))['half_duplex'] is True


CONFIG = {
    'baud': 115200, 'heartbeat': 5.0, 'connection_timeout': 15.0,
    'reconnect': 1.0, 'status_interval': 1.0, 'connect_settle': 1.5,
    'half_duplex': False,
}


def command_for(config, item, excluded=()):
    return bmcu_host_bootstrap._transport_command(
        '/opt/bmcu/scripts/bmcu_transportd.py', config, item,
        '/tmp/bmcu-transport/a.sock', '/tmp/a.log',
        '/tmp/bmcu-transport/a.status.json', 'digest', list(excluded))


def test_transport_command_full_duplex():
    command = command_for(CONFIG, {'name': 'a', 'port': '/dev/ttyUSB0', 'uid': ''})
    assert command[1:] == [
        '-I', '-S', '/opt/bmcu/scripts/bmcu_transportd.py',
        '--name', 'a', '--port', '/dev/ttyUSB0',
        '--socket', '/tmp/bmcu-transport/a.sock',
        '--baud', '115200', '--heartbeat', '5.0',
        '--connection-timeout', '15.0', '--reconnect', '1.0',
        '--status-interval', '1.0', '--connect-settle', '1.5',
        '--log-file', '/tmp/a.log',
        '--status-file', '/tmp/bmcu-transport/a.status.json',
        '--settings-digest', 'digest',
    ]


def test_transport_command_uid_adds_scan_fallback_and_exclusions():
    uid = 'AB' * 12
    command = command_for(CONFIG, {'name': 'a', 'port': '/dev/ttyUSB0', 'uid': uid},
                          excluded=['/dev/ttyUSB1', '/dev/ttyACM0'])
    assert command[-7:] == [
        '--expected-uid', uid, '--scan-fallback',
        '--exclude-port', '/dev/ttyUSB1', '--exclude-port', '/dev/ttyACM0']


def test_transport_command_half_duplex_reaches_daemon_args(monkeypatch):
    import bmcu_transportd
    config = dict(CONFIG, half_duplex=True)
    command = command_for(config, {'name': 'a', 'port': '/dev/ttyUSB0', 'uid': ''})
    assert command.count('--half-duplex') == 1
    monkeypatch.setattr('sys.argv', command[3:])
    args = bmcu_transportd.parse_args()
    assert args.half_duplex is True
    monkeypatch.setattr('sys.argv', command_for(
        CONFIG, {'name': 'a', 'port': '/dev/ttyUSB0', 'uid': ''})[3:])
    assert bmcu_transportd.parse_args().half_duplex is False
