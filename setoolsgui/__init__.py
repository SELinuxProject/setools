# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#

from .apol import run_apol

import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())
