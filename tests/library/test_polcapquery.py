# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/polcapquery.conf")
class TestPolCapQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Policy capability query with no criteria"""
        # query with no parameters gets all capabilities.
        allcaps = sorted(compiled_policy.polcaps())

        q = setools.PolCapQuery(compiled_policy)
        qcaps = sorted(q.results())

        assert allcaps == qcaps

    def test_name_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Policy capability query with exact match"""
        q = setools.PolCapQuery(compiled_policy, name="open_perms", name_regex=False)

        caps = sorted(str(c) for c in q.results())
        assert ["open_perms"] == caps

    def test_name_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Policy capability query with regex match"""
        q = setools.PolCapQuery(compiled_policy, name="pe?er", name_regex=True)

        caps = sorted(str(c) for c in q.results())
        assert ["network_peer_controls", "open_perms"] == caps
