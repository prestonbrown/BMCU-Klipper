# SPDX-License-Identifier: GPL-3.0-or-later

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
for entry in (os.path.join(ROOT, 'klippy', 'extras'), os.path.join(ROOT, 'scripts')):
    if entry not in sys.path:
        sys.path.insert(0, entry)
