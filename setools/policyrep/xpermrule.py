# Derived from terule.py
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


def xperm_rule_factory(policy, symbol):
    """Factory function for creating XPERM rule objects."""

    if isinstance(symbol, qpol.qpol_xprule_t):
        return XpermRule(policy, symbol)
    else:
        raise TypeError("XPERM rules cannot be looked-up.")


def validate_ruletype(types):
    """Validate XPERM rule types."""
    for t in types:
        if t not in ["allowxperm", "auditallowxperm", "dontauditxperm", "neverallowxperm"]:
            raise exception.InvalidXpermRuleType("{0} is not a valid XPERM rule type.".format(t))


class XpermRule(rule.PolicyRule):

    """An XPERM rule."""

    @property
    def source(self):
        """The rule's source type/attribute."""
        return typeattr.type_or_attr_factory(self.policy, self.qpol_symbol.source_type(self.policy))

    @property
    def target(self):
        """The rule's target type/attribute."""
        return typeattr.type_or_attr_factory(self.policy, self.qpol_symbol.target_type(self.policy))

    def __str__(self):
        rule_string = "{0.ruletype} {0.source} {0.target}:{0.tclass} {1};".format(
            self, self.qpol_symbol.xprule_xperm_string(self.policy))
        return rule_string
