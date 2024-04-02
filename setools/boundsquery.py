# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import policyrep, query, util
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor

__all__: typing.Final[tuple[str, ...]] = ("BoundsQuery",)


class BoundsQuery(query.PolicyQuery):

    """
    Query *bounds statements.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    ruletype        The rule type(s) to match.
    """

    ruletype = CriteriaSetDescriptor[policyrep.BoundsRuletype](enum_class=policyrep.BoundsRuletype)
    parent = CriteriaDescriptor[policyrep.Type]("parent_regex")
    parent_regex: bool = False
    child = CriteriaDescriptor[policyrep.Type]("child_regex")
    child_regex: bool = False

    def results(self) -> Iterable[policyrep.Bounds]:
        """Generator which yields all matching *bounds statements."""
        self.log.info(f"Generating bounds results from {self.policy}")
        self.log.debug(f"{self.ruletype=}")
        self.log.debug(f"{self.parent=}, {self.parent_regex=}")
        self.log.debug(f"{self.child=}, {self.child_regex=}")

        for b in self.policy.bounds():
            if self.ruletype and b.ruletype not in self.ruletype:
                continue

            if self.parent and not util.match_regex(
                    b.parent,
                    self.parent,
                    self.parent_regex):
                continue

            if self.child and not util.match_regex(
                    b.child,
                    self.child,
                    self.child_regex):
                continue

            yield b
