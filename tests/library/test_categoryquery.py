# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/categoryquery.conf")
class TestCategoryQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS category query with no criteria."""
        # query with no parameters gets all categories.
        allcats = sorted(str(c) for c in compiled_policy.categories())

        q = setools.CategoryQuery(compiled_policy)
        qcats = sorted(str(c) for c in q.results())
        assert allcats == qcats

    def test_name_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS category query with exact name match."""
        q = setools.CategoryQuery(compiled_policy, name="test1")

        cats = sorted(str(c) for c in q.results())
        assert ["test1"] == cats

    def test_name_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS category query with regex name match."""
        q = setools.CategoryQuery(compiled_policy, name="test2(a|b)", name_regex=True)

        cats = sorted(str(c) for c in q.results())
        assert ["test2a", "test2b"] == cats

    def test_alias_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS category query with exact alias match."""
        q = setools.CategoryQuery(compiled_policy, alias="test10a")

        cats = sorted(str(t) for t in q.results())
        assert ["test10c1"] == cats

    def test_alias_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS category query with regex alias match."""
        q = setools.CategoryQuery(compiled_policy, alias="test11(a|b)", alias_regex=True)

        cats = sorted(str(t) for t in q.results())
        assert ["test11c1", "test11c2"] == cats
