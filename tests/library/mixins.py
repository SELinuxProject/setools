"""Unit test mixin classes."""
# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
# pylint: disable=too-few-public-methods
import pytest
import setools


class ValidateRule:

    """Mixin for validating policy rules."""

    def validate_rule(self,
                      rule: setools.policyrep.PolicyRule,
                      ruletype: setools.policyrep.PolicyEnum | str,
                      source: setools.policyrep.PolicySymbol | str,
                      target: setools.policyrep.PolicySymbol | str,
                      tclass: setools.ObjClass | str,
                      last_item: set[str] | setools.IoctlSet | setools.policyrep.PolicySymbol | str,
                      cond: str | None = None,
                      cond_block: bool | None = None,
                      xperm: str | None = None) -> None:

        """Validate a rule."""
        assert ruletype == rule.ruletype
        assert source == rule.source
        assert target == rule.target
        assert tclass == rule.tclass

        try:
            # This is the common case.
            assert last_item == rule.perms
        except (AttributeError, setools.exception.RuleUseError):
            assert last_item == rule.default

        if cond:
            assert cond == rule.conditional
        else:
            with pytest.raises(setools.exception.RuleNotConditional):
                rule.conditional

        if cond_block is not None:
            assert cond_block == rule.conditional_block

        if xperm:
            assert xperm == rule.xperm_type
            assert rule.extended
        else:
            with pytest.raises(AttributeError):
                rule.xperm_type
            assert not rule.extended
