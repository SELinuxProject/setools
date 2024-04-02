# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from dataclasses import dataclass

from ..policyrep import Context, Genfscon

from .context import ContextWrapper
from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, Wrapper


@dataclass(frozen=True, order=True)
class ModifiedGenfscon(DifferenceResult):

    """Difference details for a modified genfscons."""

    rule: Genfscon
    added_context: Context
    removed_context: Context


class GenfsconsDifference(Difference):

    """Determine the difference in genfscon rules between two policies."""

    def diff_genfscons(self) -> None:
        """Generate the difference in genfscon rules between the policies."""

        self.log.info(
            f"Generating genfscon differences from {self.left_policy} to {self.right_policy}")

        self.added_genfscons, self.removed_genfscons, matched = self._set_diff(
            (GenfsconWrapper(fs) for fs in self.left_policy.genfscons()),
            (GenfsconWrapper(fs) for fs in self.right_policy.genfscons()))

        self.modified_genfscons = list[ModifiedGenfscon]()

        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to context
            if ContextWrapper(left_rule.context) != ContextWrapper(right_rule.context):
                self.modified_genfscons.append(ModifiedGenfscon(left_rule,
                                                                right_rule.context,
                                                                left_rule.context))

    added_genfscons = DiffResultDescriptor[Genfscon](diff_genfscons)
    removed_genfscons = DiffResultDescriptor[Genfscon](diff_genfscons)
    modified_genfscons = DiffResultDescriptor[ModifiedGenfscon](diff_genfscons)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting genfscon rule differences")
        del self.added_genfscons
        del self.removed_genfscons
        del self.modified_genfscons


class GenfsconWrapper(Wrapper[Genfscon]):

    """Wrap genfscon rules to allow set operations."""

    __slots__ = ("fs", "path", "filetype", "context")

    def __init__(self, rule: Genfscon) -> None:
        self.origin = rule
        self.fs = rule.fs
        self.path = rule.path
        self.filetype = rule.filetype
        self.context = ContextWrapper(rule.context)
        self.key = hash(rule)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        return self.fs == other.fs and \
            self.path == other.path and \
            self.filetype == other.filetype
