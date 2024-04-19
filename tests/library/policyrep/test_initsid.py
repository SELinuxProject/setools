# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/policyrep/initsid.conf")
class TestInitialSID:

    def test_string(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """InitialSID: basic string rendering."""
        sids = list(compiled_policy.initialsids())
        assert len(sids) == 1
        assert "kernel" == str(sids[0])

    def test_context(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """InitialSID: context."""
        sids = list(compiled_policy.initialsids())
        assert len(sids) == 1
        assert "system:system:system:s0" == sids[0].context, sids[0].context

    def test_statement(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """InitialSID: statement."""
        sids = list(compiled_policy.initialsids())
        assert len(sids) == 1
        assert "sid kernel system:system:system:s0" == sids[0].statement(), sids[0].statement()
