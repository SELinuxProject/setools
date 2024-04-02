# Copyright 2020, Microsoft Corporation
#
# SPDX-License-Identifier: LGPL-2.1-only
#

import typing

# This is a separate file to break a circular import.
CHECK_TYPE_KEY: typing.Final[str] = "check_type"
CHECK_DESC_KEY: typing.Final[str] = "desc"
CHECK_DISABLE: typing.Final[str] = "disable"

GLOBAL_CONFIG_KEYS: typing.Final[frozenset[str]] = frozenset((CHECK_TYPE_KEY,
                                                              CHECK_DESC_KEY,
                                                              CHECK_DISABLE))

__all__: typing.Final[tuple[str, ...]] = ("CHECK_TYPE_KEY",
                                          "CHECK_DESC_KEY",
                                          "CHECK_DISABLE",
                                          "GLOBAL_CONFIG_KEYS")
