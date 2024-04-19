"""Unit test mixin classes."""
# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
# pylint: disable=too-few-public-methods
import pytest
import setools


def validate_rule(rule: setools.policyrep.PolicyRule,
                  ruletype: setools.policyrep.PolicyEnum | str,
                  source: setools.policyrep.PolicySymbol | str,
                  target: setools.policyrep.PolicySymbol | str,
                  /, *,
                  tclass: setools.ObjClass | str | None = None,
                  perms: set[str] | setools.IoctlSet | None = None,
                  default: setools.policyrep.PolicySymbol | str | None = None,
                  cond: str | None = None,
                  cond_block: bool | None = None,
                  xperm: str | None = None) -> None:

    """Validate a rule."""
    assert ruletype == rule.ruletype
    assert source == rule.source
    assert target == rule.target

    if tclass is not None:
        assert tclass == rule.tclass

    if perms is not None:
        assert perms == rule.perms

    elif default is not None:
        assert default == rule.default

    if cond:
        assert cond == rule.conditional
        assert cond_block == rule.conditional_block
    else:
        with pytest.raises(setools.exception.RuleNotConditional):
            rule.conditional
        with pytest.raises(setools.exception.RuleNotConditional):
            rule.conditional_block

    if xperm:
        assert xperm == rule.xperm_type
        assert rule.extended
    else:
        assert not rule.extended
