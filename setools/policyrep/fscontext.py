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
import stat

from . import exception
from . import qpol
from . import symbol
from . import context


def validate_ruletype(t):
    """Validate fs_use_* rule types."""
    if t not in ["fs_use_xattr", "fs_use_trans", "fs_use_task"]:
        raise exception.InvalidFSUseType("{0} is not a valid fs_use_* type.".format(t))

    return t


def fs_use_factory(policy, name):
    """Factory function for creating fs_use_* objects."""

    if not isinstance(name, qpol.qpol_fs_use_t):
        raise TypeError("fs_use_* cannot be looked-up.")

    return FSUse(policy, name)


def genfscon_factory(policy, name):
    """Factory function for creating genfscon objects."""

    if not isinstance(name, qpol.qpol_genfscon_t):
        raise TypeError("Genfscons cannot be looked-up.")

    return Genfscon(policy, name)


class FSContext(symbol.PolicySymbol):

    """Base class for in-policy labeling rules."""

    def __str__(self):
        raise NotImplementedError

    @property
    def fs(self):
        """The filesystem type for this statement."""
        return self.qpol_symbol.name(self.policy)

    @property
    def context(self):
        """The context for this statement."""
        return context.context_factory(self.policy, self.qpol_symbol.context(self.policy))

    def statement(self):
        return str(self)


class GenfsFiletype(int):

    """
    A genfscon file type.

    The possible values are equivalent to file type
    values in the stat module, e.g. S_IFBLK, but
    overrides the string representation with the
    corresponding genfscon file type string
    (-b, -c, etc.)  If the genfscon has no specific
    file type, this is 0, (empty string).
    """

    _filetype_to_text = {
        0: "",
        stat.S_IFBLK: "-b",
        stat.S_IFCHR: "-c",
        stat.S_IFDIR: "-d",
        stat.S_IFIFO: "-p",
        stat.S_IFREG: "--",
        stat.S_IFLNK: "-l",
        stat.S_IFSOCK: "-s"}

    def __str__(self):
        return self._filetype_to_text[self]


class Genfscon(FSContext):

    """A genfscon statement."""

    def __str__(self):
        return "genfscon {0.fs} {0.path} {0.filetype} {0.context}".format(self)

    def __hash__(self):
        return hash("genfscon|{0.fs}|{0.path}|{0.filetype}".format(self))

    def __eq__(self, other):
        # Libqpol allocates new C objects in the
        # genfscons iterator, so pointer comparison
        # in the PolicySymbol object doesn't work.
        try:
            return (self.fs == other.fs and
                    self.path == other.path and
                    self.filetype == other.filetype and
                    self.context == other.context)
        except AttributeError:
            return str(self) == str(other)

    @property
    def filetype(self):
        """The file type (e.g. stat.S_IFBLK) for this genfscon statement."""
        return GenfsFiletype(self.qpol_symbol.object_class(self.policy))

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

    def __hash__(self):
        return hash("{0.ruletype}|{0.fs}".format(self))

    @property
    def ruletype(self):
        """The rule type for this fs_use_* statement."""
        return self._ruletype_to_text[self.qpol_symbol.behavior(self.policy)]
