# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/boundsquery.conf")
class TestBoundsQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Bounds query with no criteria."""
        # query with no parameters gets all bounds.
        allbounds = sorted(compiled_policy.bounds())

        q = setools.BoundsQuery(compiled_policy)
        qbounds = sorted(q.results())

        assert allbounds == qbounds

    def test_parent_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Bounds query with exact parent match."""
        q = setools.BoundsQuery(compiled_policy, parent="test1_parent", parent_regex=False)
        qbounds = sorted(q.results())
        assert 1 == len(qbounds)

        b = qbounds[0]
        assert setools.BoundsRuletype.typebounds == b.ruletype
        assert "test1_parent" == b.parent
        assert "test1_child" == b.child

    def test_parent_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Bounds query with regex parent match."""
        q = setools.BoundsQuery(compiled_policy, parent="test2_parent?", parent_regex=True)
        qbounds = sorted(q.results())
        assert 2 == len(qbounds)

        b = qbounds[0]
        assert setools.BoundsRuletype.typebounds == b.ruletype
        assert "test2_parent1" == b.parent
        assert "test2_child2" == b.child

        b = qbounds[1]
        assert setools.BoundsRuletype.typebounds == b.ruletype
        assert "test2_parent2" == b.parent
        assert "test2_child1" == b.child

    def test_child_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Bounds query with exact child match."""
        q = setools.BoundsQuery(compiled_policy, child="test10_child", child_regex=False)
        qbounds = sorted(q.results())
        assert 1 == len(qbounds)

        b = qbounds[0]
        assert setools.BoundsRuletype.typebounds == b.ruletype
        assert "test10_parent" == b.parent
        assert "test10_child" == b.child

    def test_child_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Bounds query with regex child match."""
        q = setools.BoundsQuery(compiled_policy, child="test11_child?", child_regex=True)
        qbounds = sorted(q.results())
        assert 2 == len(qbounds)

        b = qbounds[0]
        assert setools.BoundsRuletype.typebounds == b.ruletype
        assert "test11_parent1" == b.parent
        assert "test11_child2" == b.child

        b = qbounds[1]
        assert setools.BoundsRuletype.typebounds == b.ruletype
        assert "test11_parent2" == b.parent
        assert "test11_child1" == b.child
