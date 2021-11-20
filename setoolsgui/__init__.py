# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#

from .apol import ApolMainWindow
from . import widget

import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())
