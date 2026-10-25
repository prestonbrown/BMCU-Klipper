# SPDX-License-Identifier: GPL-3.0-or-later

import bmcu_host_bootstrap


def test_transport_config_half_duplex(tmp_path):
    path = tmp_path / 'bmcu.cfg'
    path.write_text('[bmcu]\n')
    assert bmcu_host_bootstrap._transport_config(str(path))['half_duplex'] is False
    path.write_text('[bmcu]\nhalf_duplex: True\n')
    assert bmcu_host_bootstrap._transport_config(str(path))['half_duplex'] is True
