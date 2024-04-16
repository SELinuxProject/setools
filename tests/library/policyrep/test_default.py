# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
from collections import defaultdict

import pytest
import setools


@pytest.mark.obj_args("tests/library/policyrep/default.conf")
class TestDefault:

    @pytest.fixture(autouse=True)
    def _load_defaults(self, compiled_policy: setools.SELinuxPolicy) -> None:
        self.defaults = defaultdict[str, list[setools.Default]](list)
        for d in compiled_policy.defaults():
            self.defaults[d.tclass.name].append(d)

    def test_user(self) -> None:
        """Default: default_user methods/attributes."""
        d = self.defaults["infoflow"].pop()
        assert setools.DefaultRuletype.default_user == d.ruletype
        assert "infoflow" == d.tclass
        assert setools.DefaultValue.target == d.default
        assert "default_user infoflow target;" == str(d)
        assert str(d) == d.statement()

    def test_role(self) -> None:
        """Default: default_role methods/attributes."""
        d = self.defaults["infoflow2"].pop()
        assert setools.DefaultRuletype.default_role, d.ruletype
        assert "infoflow2" == d.tclass
        assert setools.DefaultValue.source, d.default
        assert "default_role infoflow2 source;" == str(d)
        assert str(d) == d.statement()

    def test_type(self) -> None:
        """Default: default_type methods/attributes."""
        d = self.defaults["infoflow3"].pop()
        assert setools.DefaultRuletype.default_type, d.ruletype
        assert "infoflow3" == d.tclass
        assert setools.DefaultValue.target, d.default
        assert "default_type infoflow3 target;" == str(d)
        assert str(d) == d.statement()

    def test_range(self) -> None:
        """Default: default_range methods/attributes."""
        d = self.defaults["infoflow4"].pop()
        assert isinstance(d, setools.DefaultRange)
        assert setools.DefaultRuletype.default_range, d.ruletype
        assert "infoflow4" == d.tclass
        assert setools.DefaultValue.source, d.default
        assert setools.DefaultRangeValue.high == d.default_range
        assert "default_range infoflow4 source high;" == str(d)
        assert str(d) == d.statement()
