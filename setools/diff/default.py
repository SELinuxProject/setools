# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from dataclasses import dataclass

from ..policyrep import AnyDefault, Default, DefaultValue, DefaultRangeValue

from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, SymbolWrapper, Wrapper


@dataclass(frozen=True, order=True)
class ModifiedDefault(DifferenceResult):

    """Difference details for a modified default_*."""

    rule: Default
    added_default: DefaultValue | None
    removed_default: DefaultValue | None
    added_default_range: DefaultRangeValue | None
    removed_default_range: DefaultRangeValue | None


class DefaultsDifference(Difference):

    """Determine the difference in default_* between two policies."""

    def diff_defaults(self) -> None:
        """Generate the difference in type defaults between the policies."""

        self.log.info(
            f"Generating default_* differences from {self.left_policy} to {self.right_policy}")

        self.added_defaults, self.removed_defaults, matched_defaults = self._set_diff(
            (DefaultWrapper(d) for d in self.left_policy.defaults()),
            (DefaultWrapper(d) for d in self.right_policy.defaults()))

        self.modified_defaults = list[ModifiedDefault]()

        for left_default, right_default in matched_defaults:
            # Criteria for modified defaults
            # 1. change to default setting
            # 2. change to default range

            if left_default.default != right_default.default:
                removed_default = left_default.default
                added_default = right_default.default
            else:
                removed_default = None
                added_default = None

            try:
                if left_default.default_range != right_default.default_range:
                    removed_default_range = left_default.default_range
                    added_default_range = right_default.default_range
                else:
                    removed_default_range = None
                    added_default_range = None
            except AttributeError:
                removed_default_range = None
                added_default_range = None

            if removed_default or removed_default_range:
                self.modified_defaults.append(
                    ModifiedDefault(left_default,
                                    added_default,
                                    removed_default,
                                    added_default_range,
                                    removed_default_range))

    added_defaults = DiffResultDescriptor[AnyDefault](diff_defaults)
    removed_defaults = DiffResultDescriptor[AnyDefault](diff_defaults)
    modified_defaults = DiffResultDescriptor[ModifiedDefault](diff_defaults)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting default_* differences")
        del self.added_defaults
        del self.removed_defaults
        del self.modified_defaults


class DefaultWrapper(Wrapper[Default]):

    """Wrap default_* to allow comparisons."""

    __slots__ = ("ruletype", "tclass")

    def __init__(self, default: Default) -> None:
        self.origin = default
        self.ruletype = default.ruletype
        self.tclass = SymbolWrapper(default.tclass)
        self.key = hash(default)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        return self.ruletype == other.ruletype and \
            self.tclass == other.tclass
