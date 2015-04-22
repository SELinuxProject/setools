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


class PolicySymbol(object):

    """This is a base class for all policy objects."""

    def __init__(self, policy, qpol_symbol):
        """
        Parameters:
        policy        The low-level policy object.
        qpol_symbol   The low-level policy symbol object.
        """

        assert qpol_symbol

        self.policy = policy
        self.qpol_symbol = qpol_symbol

    def __str__(self):
        return self.qpol_symbol.name(self.policy)

    def __hash__(self):
        return hash(self.qpol_symbol.name(self.policy))

    def __eq__(self, other):
        try:
            return self.qpol_symbol.this == other.qpol_symbol.this
        except AttributeError:
            return str(self) == str(other)

    def __ne__(self, other):
        return not self == other

    def __lt__(self, other):
        """Comparison used by Python sorting functions."""
        return str(self) < str(other)

    def __repr__(self):
        return "<{0.__class__.__name__}(<qpol_policy_t id={1}>,\"{0}\")>".format(
            self, id(self.policy))

    def __deepcopy__(self, memo):
        # shallow copy as all of the members are immutable
        cls = self.__class__
        newobj = cls.__new__(cls)
        newobj.policy = self.policy
        newobj.qpol_symbol = self.qpol_symbol
        memo[id(self)] = newobj
        return newobj

    def statement(self):
        """
        A rendering of the policy statement.  This should be
        overridden by subclasses.
        """
        raise NotImplementedError
