# Copyright 2015, Tresys Technology, LLC
# Copyright 2024, Sealing Technologies, Inc.
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/constraintquery.conf")
class TestConstraintQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint query with no criteria."""
        allconstraint = sorted(c.tclass for c in compiled_policy.constraints())

        q = setools.ConstraintQuery(compiled_policy)
        qconstraint = sorted(c.tclass for c in q.results())
        assert allconstraint == qconstraint

    def test_ruletype(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint query with rule type match."""
        q = setools.ConstraintQuery(compiled_policy, ruletype=["mlsconstrain"])

        constraint = sorted(c.tclass for c in q.results())
        assert ["test1"] == constraint

    def test_class_list(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint query with object class list match."""
        q = setools.ConstraintQuery(compiled_policy, tclass=["test11a", "test11b"])

        constraint = sorted(c.tclass for c in q.results())
        assert ["test11a", "test11b"] == constraint

    def test_class_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint query with object class regex match."""
        q = setools.ConstraintQuery(compiled_policy, tclass="test12(a|c)", tclass_regex=True)

        constraint = sorted(c.tclass for c in q.results())
        assert ["test12a", "test12c"] == constraint

    def test_perms_any(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint query with permission set intersection match."""
        q = setools.ConstraintQuery(compiled_policy, perms=["test20ap", "test20bp"])

        constraint = sorted(c.tclass for c in q.results())
        assert ["test20a", "test20b"] == constraint

    def test_perms_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint query with permission set equality match."""
        q = setools.ConstraintQuery(compiled_policy, perms=["test21ap", "test21bp"],
                                    perms_equal=True)

        constraint = sorted(c.tclass for c in q.results())
        assert ["test21c"] == constraint

    def test_role_match_single(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint query with role match."""
        q = setools.ConstraintQuery(compiled_policy, role="test30r")

        constraint = sorted(c.tclass for c in q.results())
        assert ["test30"] == constraint

    def test_role_match_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint query with regex role match."""
        q = setools.ConstraintQuery(compiled_policy, role="test31r.", role_regex=True)

        constraint = sorted(c.tclass for c in q.results())
        assert ["test31a", "test31b"] == constraint

    def test_type_match_single(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint query with type match."""
        q = setools.ConstraintQuery(compiled_policy, type_="test40t")

        constraint = sorted(c.tclass for c in q.results())
        assert ["test40"] == constraint

    def test_type_match_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint query with regex type match."""
        q = setools.ConstraintQuery(compiled_policy, type_="test41t.", type_regex=True)

        constraint = sorted(c.tclass for c in q.results())
        assert ["test41a", "test41b"] == constraint

    def test_user_match_single(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint query with user match."""
        q = setools.ConstraintQuery(compiled_policy, user="test50u")

        constraint = sorted(c.tclass for c in q.results())
        assert ["test50"] == constraint

    def test_user_match_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint query with regex user match."""
        q = setools.ConstraintQuery(compiled_policy, user="test51u.", user_regex=True)

        constraint = sorted(c.tclass for c in q.results())
        assert ["test51a", "test51b"] == constraint

    def test_or_and_parens(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint with an or expression anded with another expression"""
        q = setools.ConstraintQuery(compiled_policy, tclass=["test52a"])

        constraint = sorted(str(c.expression) for c in q.results())
        assert ["( r1 == system or r2 == system ) and u1 == u2"] == constraint

    def test_or_and_no_parens(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Constraint with an or expression anded with another expression"""
        q = setools.ConstraintQuery(compiled_policy, tclass=["test52b"])

        constraint = sorted(str(c.expression) for c in q.results())
        assert ["r1 == system or r2 == system and u1 == u2"] == constraint
