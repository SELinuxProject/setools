# Copyright 2014, Tresys Technology, LLC
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


def validate_ruletype(types):
    """Validate MLS rule types."""
    for t in types:
        if t not in ["range_transition"]:
            raise exception.InvalidMLSRuleType("{0} is not a valid MLS rule type.".format(t))


class MLSRule(rule.PolicyRule):

    """An MLS rule."""

    def __str__(self):
        # TODO: If we ever get more MLS rules, fix this format.
        return "range_transition {0.source} {0.target}:{0.tclass} {0.default};".format(self)

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
