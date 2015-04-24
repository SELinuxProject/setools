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
from . import context


def initialsid_factory(policy, name):
    """Factory function for creating initial sid objects."""

    if isinstance(name, InitialSID):
        assert name.policy == policy
        return name
    elif isinstance(name, qpol.qpol_isid_t):
        return InitialSID(policy, name)

    try:
        return InitialSID(policy, qpol.qpol_isid_t(policy, name))
    except ValueError:
        raise exception.InvalidInitialSid("{0} is not a valid initial sid".format(name))


class InitialSID(symbol.PolicySymbol):

    """An initial SID statement."""

    @property
    def context(self):
        """The context for this initial SID."""
        return context.context_factory(self.policy, self.qpol_symbol.context(self.policy))

    def statement(self):
        return "sid {0} {0.context}".format(self)
