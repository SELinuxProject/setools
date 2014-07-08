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
import setools.qpol as qpol

import rule
import typeattr
import mls
import objclass
import boolcond


class MLSRule(rule.PolicyRule):

    """An MLS rule."""

    def __str__(self):
        # TODO: If we ever get more MLS rules, fix this format.
        return "range_transition {0.source} {0.target}:{0.tclass} {0.default};".format(self)

    @property
    def ruletype(self):
        """The rule type."""
        return "range_transition"

    @property
    def source(self):
        """The rule's source type/attribute."""
        return typeattr.TypeAttr(self.policy, self.qpol_symbol.get_source_type(self.policy))

    @property
    def target(self):
        """The rule's target type/attribute."""
        return typeattr.TypeAttr(self.policy, self.qpol_symbol.get_target_type(self.policy))

    @property
    def tclass(self):
        """The rule's object class."""
        return objclass.ObjClass(self.policy, self.qpol_symbol.get_target_class(self.policy))

    @property
    def default(self):
        """The rule's default range."""
        return mls.MLSRange(self.policy, self.qpol_symbol.get_range(self.policy))
