# Copyright 2020, Microsoft Corporation
#
# SPDX-License-Identifier: GPL-2.0-only
#
from setools.checker import util


class TestCheckerUtil:

    def test_config_bool_value(self):
        """Test config_bool_value"""
        assert util.config_bool_value(" TrUe ")
        assert (util.config_bool_value(" 1 "))
        assert (util.config_bool_value(" YeS "))
        assert not util.config_bool_value(" FalsE ")
        assert not util.config_bool_value(" 0 ")
        assert not util.config_bool_value(" No ")

        assert util.config_bool_value(True)
        assert not util.config_bool_value(None)
        assert not util.config_bool_value(False)
