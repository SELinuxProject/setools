# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import logging
import re
from typing import Iterable

from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor
from .policyrep import Bounds, BoundsRuletype
from .query import PolicyQuery
from .util import match_regex


class BoundsQuery(PolicyQuery):

    """
    Query *bounds statements.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    ruletype        The rule type(s) to match.
    """

    ruletype = CriteriaSetDescriptor(enum_class=BoundsRuletype)
    parent = CriteriaDescriptor("parent_regex")
    parent_regex: bool = False
    child = CriteriaDescriptor("child_regex")
    child_regex: bool = False

    def __init__(self, policy, **kwargs) -> None:
        super(BoundsQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self) -> Iterable[Bounds]:
        """Generator which yields all matching *bounds statements."""
        self.log.info("Generating bounds results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype}".format(self))
        self.log.debug("Parent: {0.parent!r}, regex: {0.parent_regex}".format(self))
        self.log.debug("Child: {0.child!r}, regex: {0.child_regex}".format(self))

        for b in self.policy.bounds():
            if self.ruletype and b.ruletype not in self.ruletype:
                continue

            if self.parent and not match_regex(
                    b.parent,
                    self.parent,
                    self.parent_regex):
                continue

            if self.child and not match_regex(
                    b.child,
                    self.child,
                    self.child_regex):
                continue

            yield b
