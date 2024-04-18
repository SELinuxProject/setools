# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/boolquery.conf")
class TestBoolQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Boolean query with no criteria."""
        # query with no parameters gets all Booleans.
        allbools = sorted(str(b) for b in compiled_policy.bools())

        q = setools.BoolQuery(compiled_policy)
        qbools = sorted(str(b) for b in q.results())

        assert allbools == qbools

    def test_name_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Boolean query with exact match"""
        q = setools.BoolQuery(compiled_policy, name="test1")

        bools = sorted(str(b) for b in q.results())
        assert ["test1"] == bools

    def test_name_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Boolean query with regex match."""
        q = setools.BoolQuery(compiled_policy, name="test2(a|b)", name_regex=True)

        bools = sorted(str(b) for b in q.results())
        assert ["test2a", "test2b"] == bools

    def test_default(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Boolean query with default state match."""
        q = setools.BoolQuery(compiled_policy, default=False)

        bools = sorted(str(b) for b in q.results())
        assert ["test10a", "test10b"] == bools
