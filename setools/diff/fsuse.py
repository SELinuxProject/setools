# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from dataclasses import dataclass

from ..policyrep import Context, FSUse

from .context import ContextWrapper
from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, Wrapper


@dataclass(frozen=True, order=True)
class ModifiedFSUse(DifferenceResult):

    """Difference details for a modified fs_use_*."""

    rule: FSUse
    added_context: Context
    removed_context: Context


class FSUsesDifference(Difference):

    """Determine the difference in fs_use_* rules between two policies."""

    def diff_fs_uses(self) -> None:
        """Generate the difference in fs_use rules between the policies."""

        self.log.info(
            f"Generating fs_use_* differences from {self.left_policy} to {self.right_policy}")

        self.added_fs_uses, self.removed_fs_uses, matched = self._set_diff(
            (FSUseWrapper(fs) for fs in self.left_policy.fs_uses()),
            (FSUseWrapper(fs) for fs in self.right_policy.fs_uses()))

        self.modified_fs_uses = list[ModifiedFSUse]()

        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to context
            if ContextWrapper(left_rule.context) != ContextWrapper(right_rule.context):
                self.modified_fs_uses.append(ModifiedFSUse(left_rule,
                                                           right_rule.context,
                                                           left_rule.context))

    added_fs_uses = DiffResultDescriptor[FSUse](diff_fs_uses)
    removed_fs_uses = DiffResultDescriptor[FSUse](diff_fs_uses)
    modified_fs_uses = DiffResultDescriptor[ModifiedFSUse](diff_fs_uses)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting fs_use_* rule differences")
        del self.added_fs_uses
        del self.removed_fs_uses
        del self.modified_fs_uses


class FSUseWrapper(Wrapper[FSUse]):

    """Wrap fs_use_* rules to allow set operations."""

    __slots__ = ("ruletype", "fs", "context")

    def __init__(self, rule: FSUse) -> None:
        self.origin = rule
        self.ruletype = rule.ruletype
        self.fs = rule.fs
        self.context = ContextWrapper(rule.context)
        self.key = hash(rule)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        return self.ruletype == other.ruletype and self.fs == other.fs
