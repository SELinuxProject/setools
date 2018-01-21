# Copyright 2014, 2016, Tresys Technology, LLC
# Copyright 2016-2018, Chris PeBenito <pebenito@ieee.org>
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

#
# FSUse factory functions
#
cdef inline fs_use_iterator_factory(SELinuxPolicy policy, sepol.ocontext_t *head):
    """Factory function for creating FSUse iterators."""
    i = FSUseIterator()
    i.policy = policy
    i.head = i.curr = head
    return i


cdef inline FSUse fs_use_factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
    """Factory function for creating FSUse objects."""
    r = FSUse()
    r.policy = policy
    r.handle = symbol
    return r


#
# Genfscon factory functions
#
cdef inline Genfscon genfscon_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Genfscon objects."""
    return genfscon_factory(policy, <const qpol_genfscon_t *> symbol.obj)


cdef inline Genfscon genfscon_factory(SELinuxPolicy policy, const qpol_genfscon_t *symbol):
    """Factory function for creating Genfscon objects."""
    r = Genfscon()
    r.policy = policy
    r.handle = symbol
    return r


#
# Classes
#
class FSUseRuletype(PolicyEnum):

    """Enumeration of fs_use_* rule types."""
    # there are more rule types, but modern SELinux
    # only supports these three.

    fs_use_xattr = sepol.SECURITY_FS_USE_XATTR
    fs_use_trans = sepol.SECURITY_FS_USE_TRANS
    fs_use_task = sepol.SECURITY_FS_USE_TASK


cdef class FSUse(Ocontext):

    """An fs_use_* statement."""

    def __str__(self):
        return "{0.ruletype} {0.fs} {0.context};".format(self)

    def __hash__(self):
        return hash("{0.ruletype}|{0.fs}".format(self))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    @property
    def fs(self):
        """The filesystem type for this statement."""
        return intern(self.handle.u.name)

    @property
    def ruletype(self):
        """The rule type for this fs_use_* statement."""
        return FSUseRuletype(self.handle.v.behavior)


cdef class FSUseIterator(OcontextIterator):

    """Iterator for fs_use_* statements in the policy."""

    def __next__(self):
        super().__next__()
        return fs_use_factory(self.policy, self.ocon)


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

    _filetype_to_text = {0: "",
                         S_IFBLK: "-b",
                         S_IFCHR: "-c",
                         S_IFDIR: "-d",
                         S_IFIFO: "-p",
                         S_IFREG: "--",
                         S_IFLNK: "-l",
                         S_IFSOCK: "-s"}

    def __str__(self):
        return self._filetype_to_text[self]


cdef class Genfscon(PolicySymbol):

    """A genfscon statement."""

    cdef const qpol_genfscon_t *handle

    _qpol_to_stat = {0: 0,
                     QPOL_CLASS_BLK_FILE: S_IFBLK,
                     QPOL_CLASS_CHR_FILE: S_IFCHR,
                     QPOL_CLASS_DIR: S_IFDIR,
                     QPOL_CLASS_FIFO_FILE: S_IFIFO,
                     QPOL_CLASS_FILE: S_IFREG,
                     QPOL_CLASS_LNK_FILE: S_IFLNK,
                     QPOL_CLASS_SOCK_FILE: S_IFSOCK}

    def __str__(self):
        return "genfscon {0.fs} {0.path} {0.filetype} {0.context}".format(self)

    def __hash__(self):
        return hash("genfscon|{0.fs}|{0.path}|{0.filetype}".format(self))

    def __eq__(self, other):
        # TODO: free the objects
        # TODO: see if this can be fixed
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

    def _eq(self, Genfscon other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def context(self):
        """The context for this statement."""
        cdef const qpol_context_t *ctx
        if qpol_genfscon_get_context(self.policy.handle, self.handle, &ctx):
            ex = LowLevelPolicyError("Error reading genfscon file system context: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return context_factory(self.policy, ctx)

    @property
    def filetype(self):
        """The file type (e.g. stat.S_IFBLK) for this genfscon statement."""
        cdef uint32_t cls
        if qpol_genfscon_get_class(self.policy.handle, self.handle, &cls):
            ex = LowLevelPolicyError("Error reading genfscon class: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return GenfsFiletype(self._qpol_to_stat[cls])

    @property
    def fs(self):
        """The filesystem type for this statement."""
        cdef const char *name
        if qpol_genfscon_get_name(self.policy.handle, self.handle, &name):
            ex = LowLevelPolicyError("Error reading genfscon file system type: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return intern(name)

    @property
    def path(self):
        """The path for this genfscon statement."""
        cdef const char *path
        if qpol_genfscon_get_path(self.policy.handle, self.handle, &path):
            ex = LowLevelPolicyError("Error reading genfscon file system path: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return intern(path)

    def statement(self):
        return str(self)
