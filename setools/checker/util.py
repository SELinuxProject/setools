# Copyright 2020, Microsoft Corporation
#
# SPDX-License-Identifier: LGPL-2.1-only
#


def config_bool_value(value) -> bool:
    """Convert a boolean configuration value."""

    if isinstance(value, str):
        if value and value.strip().lower() in ("yes", "true", "1"):
            return True

        return False

    return bool(value)
