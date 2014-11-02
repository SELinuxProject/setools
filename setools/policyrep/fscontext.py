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
from . import qpol
from . import symbol
from . import context


class FSContext(symbol.PolicySymbol):

    """Abstract base class for in-policy labeling rules."""

    def __str__(self):
        raise NotImplementedError

    @property
    def fs(self):
        """The filesystem type for this statement."""
        return self.qpol_symbol.name(self.policy)

    @property
    def context(self):
        """The context for this statement."""
        return context.Context(self.policy, self.qpol_symbol.context(self.policy))

    def statement(self):
        return str(self)


class Genfscon(FSContext):

    """A genfscon statement."""

    def __str__(self):
        return "genfscon {0.fs} {0.path} {0.context}".format(self)

    def filetype(self):
        """The file type for this genfscon statement."""
        raise NotImplementedError

    @property
    def path(self):
        """The path for this genfscon statement."""
        return self.qpol_symbol.path(self.policy)


class FSUse(FSContext):

    """A fs_use_* statement."""

    # there are more rule types, but modern SELinux
    # only supports these three.
    _ruletype_to_text = {
        qpol.QPOL_FS_USE_XATTR: 'fs_use_xattr',
        qpol.QPOL_FS_USE_TRANS: 'fs_use_trans',
        qpol.QPOL_FS_USE_TASK: 'fs_use_task'}

    def __str__(self):
        return "{0.ruletype} {0.fs} {0.context};".format(self)

    @property
    def ruletype(self):
        """The rule type for this fs_use_* statement."""
        return self._ruletype_to_text[self.qpol_symbol.behavior(self.policy)]
