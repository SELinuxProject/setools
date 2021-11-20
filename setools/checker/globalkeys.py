# Copyright 2020, Microsoft Corporation
#
# SPDX-License-Identifier: LGPL-2.1-only
#

# This is a separate file to break a circular import.
CHECK_TYPE_KEY = "check_type"
CHECK_DESC_KEY = "desc"
CHECK_DISABLE = "disable"

GLOBAL_CONFIG_KEYS = frozenset((CHECK_TYPE_KEY, CHECK_DESC_KEY, CHECK_DISABLE))
