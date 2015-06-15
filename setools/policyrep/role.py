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
from . import symbol
from . import typeattr


def role_factory(qpol_policy, name):
    """Factory function for creating Role objects."""

    if isinstance(name, Role):
        assert name.policy == qpol_policy
        return name
    elif isinstance(name, qpol.qpol_role_t):
        return Role(qpol_policy, name)

    try:
        return Role(qpol_policy, qpol.qpol_role_t(qpol_policy, str(name)))
    except ValueError:
        raise exception.InvalidRole("{0} is not a valid role".format(name))


class BaseRole(symbol.PolicySymbol):

    """Role/role attribute base class."""

    def expand(self):
        raise NotImplementedError

    def types(self):
        raise NotImplementedError


class Role(BaseRole):

    """A role."""

    def expand(self):
        """Generator that expands this into its member roles."""
        yield self

    def types(self):
        """Generator which yields the role's set of types."""

        for type_ in self.qpol_symbol.type_iter(self.policy):
            yield typeattr.type_or_attr_factory(self.policy, type_)

    def statement(self):
        types = list(str(t) for t in self.types())
        stmt = "role {0}".format(self)
        if types:
            if (len(types) > 1):
                stmt += " types {{ {0} }}".format(' '.join(types))
            else:
                stmt += " types {0}".format(types[0])
        stmt += ";"
        return stmt


class RoleAttribute(BaseRole):

    """A role attribute."""

    pass
