# Copyright 2016, Tresys Technology, LLC
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
from .symbol import PolicySymbol
from .qpol import qpol_typebounds_t
from .typeattr import type_factory


def bounds_factory(policy, sym):
    """Factory for creating bounds statement objects."""

    if isinstance(sym, qpol_typebounds_t):
        return Bounds(policy, sym)
    else:
        raise TypeError("typebounds rules cannot be looked up.")


def validate_ruletype(t):
    """Validate *bounds rule types."""
    if t not in ["typebounds"]:
        raise exception.InvalidBoundsType("{0} is not a valid *bounds  rule type.".format(t))

    return t


class Bounds(PolicySymbol):

    """A typebounds statement."""

    def __str__(self):
        return "{0.ruletype} {0.parent} {0.child};".format(self)

    def __hash__(self):
        return hash("{0.ruletype}|{0.child};".format(self))

    ruletype = "typebounds"

    @property
    def parent(self):
        return type_factory(self.policy, self.qpol_symbol.parent_name(self.policy))

    @property
    def child(self):
        return type_factory(self.policy, self.qpol_symbol.child_name(self.policy))
