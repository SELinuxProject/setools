# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest


@pytest.mark.obj_args("tests/library/policyrep/polcap.conf")
class TestPolicyCapability:

    def test_string(self, compiled_policy):
        """PolCap: basic string rendering."""
        caps = list(compiled_policy.polcaps())
        assert len(caps) == 1
        assert "open_perms" == str(caps[0])

    def test_statement(self, compiled_policy):
        """PolCap: statement."""
        caps = list(compiled_policy.polcaps())
        assert len(caps) == 1
        assert "policycap open_perms;" == caps[0].statement()
