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
cdef inline genfscon_iterator_factory(SELinuxPolicy policy, sepol.genfs_t *head):
    """Factory function for creating genfscon iterators."""
    i = GenfsconIterator()
    i.policy = policy
    i.head = i.curr = head
    return i


cdef inline genfscon_subiterator_factory(SELinuxPolicy policy, sepol.ocontext_t *head, fstype):
    """Factory function for creating genfscon sub-iterators."""
    i = GenfsconOcontextIterator()
    i.policy = policy
    i.head = i.curr = head
    i.fs = fstype
    return i


cdef inline Genfscon genfscon_factory(SELinuxPolicy policy, sepol.ocontext_t *symbol, fstype):
    """Factory function for creating Genfscon objects."""
    r = Genfscon()
    r.policy = policy
    r.handle = symbol
    r.fs = fstype
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


cdef class Genfscon(Ocontext):

    """A genfscon statement."""

    cdef readonly str fs

    _sclass_to_stat = {0: 0,
                       sepol.SECCLASS_BLK_FILE: S_IFBLK,
                       sepol.SECCLASS_CHR_FILE: S_IFCHR,
                       sepol.SECCLASS_DIR: S_IFDIR,
                       sepol.SECCLASS_FIFO_FILE: S_IFIFO,
                       sepol.SECCLASS_FILE: S_IFREG,
                       sepol.SECCLASS_LNK_FILE: S_IFLNK,
                       sepol.SECCLASS_SOCK_FILE: S_IFSOCK}

    def __str__(self):
        return "genfscon {0.fs} {0.path} {0.filetype} {0.context}".format(self)

    def __hash__(self):
        return hash("genfscon|{0.fs}|{0.path}|{0.filetype}".format(self))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    @property
    def filetype(self):
        """The file type (e.g. stat.S_IFBLK) for this genfscon statement."""
        return GenfsFiletype(self._sclass_to_stat[self.handle.v.sclass])

    @property
    def path(self):
        """The path for this genfscon statement."""
        return intern(self.handle.u.name)


cdef class GenfsconIterator:

    """Iterator for genfscon statements in the policy."""

    cdef:
        sepol.genfs_t *head
        sepol.genfs_t *curr
        object ocon_iter
        SELinuxPolicy policy

    def __iter__(self):
        return self

    def __next__(self):
        # consume sub-iterator first, if one exists
        if self.ocon_iter:
            try:
                return self.ocon_iter.__next__()
            except StopIteration:
                # sub_iter completed, clear
                self.ocon_iter = None

        if self.curr == NULL:
            raise StopIteration

        # create a sub-iterator for this fs entry
        self.ocon_iter = genfscon_subiterator_factory(self.policy, self.curr.head,
                                                      intern(self.curr.fstype))

        self.curr = self.curr.next
        return self.ocon_iter.__next__()

    def __len__(self):
        cdef:
            size_t count = 0
            sepol.genfs_t *genfs = self.head

        while genfs:
            count += len(genfscon_subiterator_factory(self.policy, genfs.head, genfs.fstype))
            genfs = genfs.next

        return count


cdef class GenfsconOcontextIterator(OcontextIterator):

    """Sub-iterator for genfscon statements."""

    cdef str fs

    def __next__(self):
        super().__next__()
        return genfscon_factory(self.policy, self.ocon, self.fs)
