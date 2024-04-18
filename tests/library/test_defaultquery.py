# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/defaultquery.conf")
class TestDefaultQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Default query: no criteria."""
        # query with no parameters gets all defaults
        alldefaults = sorted(compiled_policy.defaults())

        q = setools.DefaultQuery(compiled_policy)
        qdefaults = sorted(q.results())

        assert alldefaults == qdefaults

    def test_ruletype(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Default query: ruletype criterion."""
        q = setools.DefaultQuery(compiled_policy, ruletype=["default_user"])
        defaults = list(q.results())
        assert 1 == len(defaults)

        d = defaults[0]
        assert setools.DefaultRuletype.default_user == d.ruletype
        assert "infoflow" == d.tclass
        assert setools.DefaultValue.target == d.default

    def test_class_list(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Default query: object class list match."""
        q = setools.DefaultQuery(compiled_policy, tclass=["infoflow3", "infoflow4"])

        defaults = sorted(d.tclass for d in q.results())
        assert ["infoflow3", "infoflow4"] == defaults

    def test_class_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Default query: object class regex match."""
        q = setools.DefaultQuery(compiled_policy, tclass="infoflow(3|5)", tclass_regex=True)

        defaults = sorted(c.tclass for c in q.results())
        assert ["infoflow3", "infoflow5"] == defaults

    def test_default(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Default query: default setting."""
        q = setools.DefaultQuery(compiled_policy, default="source")

        defaults = sorted(c.tclass for c in q.results())
        assert ["infoflow", "infoflow3"] == defaults

    def test_default_range(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Default query: default_range setting."""
        q = setools.DefaultQuery(compiled_policy, default_range="high")

        defaults = sorted(c.tclass for c in q.results())
        assert ["infoflow7"] == defaults

    def test_invalid_ruletype(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Default query: invalid ruletype"""
        with pytest.raises(KeyError):
            q = setools.DefaultQuery(compiled_policy, ruletype=["INVALID"])

    def test_invalid_class(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Default query: invalid object class"""
        with pytest.raises(setools.exception.InvalidClass):
            q = setools.DefaultQuery(compiled_policy, tclass=["INVALID"])

    def test_invalid_default_value(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Default query: invalid default value"""
        with pytest.raises(KeyError):
            q = setools.DefaultQuery(compiled_policy, default="INVALID")

    def test_invalid_default_range(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Default query: invalid default range"""
        with pytest.raises(KeyError):
            q = setools.DefaultQuery(compiled_policy, default_range="INVALID")
