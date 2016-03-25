# Copyright 2014, 2016, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
import itertools

from . import exception
from . import qpol
from . import rule
from . import typeattr
from . import mls


def mls_rule_factory(policy, symbol):
    """Factory function for creating MLS rule objects."""
    if not isinstance(symbol, qpol.qpol_range_trans_t):
        raise TypeError("MLS rules cannot be looked-up.")

    return MLSRule(policy, symbol)


def expanded_mls_rule_factory(original, source, target):
    """
    Factory function for creating expanded MLS rules.

    original    The MLS rule the expanded rule originates from.
    source      The source type of the expanded rule.
    target      The target type of the expanded rule.
    """

    if isinstance(original, ExpandedMLSRule):
        return original
    elif isinstance(original, MLSRule):
        rule = ExpandedMLSRule(original.policy, original.qpol_symbol)
    else:
        raise TypeError("The original rule must be a MLS rule class.")

    rule.source = source
    rule.target = target
    rule.origin = original
    return rule


def validate_ruletype(t):
    """Validate MLS rule types."""
    if t not in ["range_transition"]:
        raise exception.InvalidMLSRuleType("{0} is not a valid MLS rule type.".format(t))

    return t


class MLSRule(rule.PolicyRule):

    """An MLS rule."""

    def __str__(self):
        return "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default};".format(self)

    ruletype = "range_transition"

    @property
    def source(self):
        """The rule's source type/attribute."""
        return typeattr.type_or_attr_factory(self.policy, self.qpol_symbol.source_type(self.policy))

    @property
    def target(self):
        """The rule's target type/attribute."""
        return typeattr.type_or_attr_factory(self.policy, self.qpol_symbol.target_type(self.policy))

    @property
    def default(self):
        """The rule's default range."""
        return mls.range_factory(self.policy, self.qpol_symbol.range(self.policy))

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        for s, t in itertools.product(self.source.expand(), self.target.expand()):
            yield expanded_mls_rule_factory(self, s, t)


class ExpandedMLSRule(MLSRule):

    """An expanded MLS rule."""

    source = None
    target = None
    origin = None
