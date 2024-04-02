# Copyright 2014, 2016, Tresys Technology, LLC
# Copyright 2016-2018, 2020, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

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

    cdef:
        readonly object ruletype
        readonly str fs

    @staticmethod
    cdef inline FSUse factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating FSUse objects."""
        cdef FSUse f = FSUse.__new__(FSUse)
        f.policy = policy
        f.ruletype = FSUseRuletype(symbol.v.behavior)
        f.fs = intern(symbol.u.name)
        f.context = Context.factory(policy, symbol.context)
        return f

    def __hash__(self):
        return hash(f"{self.ruletype}|{self.fs}")

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    def statement(self):
        return f"{self.ruletype} {self.fs} {self.context};"


cdef class GenfsFiletype(int):

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

    cdef:
        readonly str fs
        readonly object filetype
        readonly ObjClass tclass
        readonly str path

    _sclass_to_stat = {0: 0,
                       "dir": S_IFDIR,
                       "file": S_IFREG,
                       "lnk_file": S_IFLNK,
                       "fifo_file": S_IFIFO,
                       "sock_file": S_IFSOCK,
                       "blk_file": S_IFBLK,
                       "chr_file": S_IFCHR}

    @staticmethod
    cdef inline Genfscon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol, fstype):
        """Factory function for creating Genfscon objects."""
        cdef Genfscon g = Genfscon.__new__(Genfscon)
        g.policy = policy
        g.key = <uintptr_t>symbol
        g.fs = fstype
        g.path = intern(symbol.u.name)

        if symbol.v.sclass:
            try:
                g.tclass = ObjClass.factory(policy, policy.class_value_to_datum(symbol.v.sclass-1))
                g.filetype = GenfsFiletype(Genfscon._sclass_to_stat[g.tclass.name])
            except KeyError as ex:
                log = logging.getLogger(__name__)
                log.warning("Genfscon {g.fs} {g.path} object class {g.tclass.name} does not match "
                            "a file object class. Dropping file type.")
                g.filetype = GenfsFiletype(0)
                g.tclass = None

        else:
            g.filetype = GenfsFiletype(0)
            g.tclass = None

        g.context = Context.factory(policy, symbol.context)
        return g

    def __hash__(self):
        return hash(f"genfscon|{self.fs}|{self.path}|{self.filetype}")

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    def statement(self):
        return f"genfscon {self.fs} {self.path} {self.filetype} {self.context}"


#
# Iterators
#
cdef class FSUseIterator(OcontextIterator):

    """Iterator for fs_use_* statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating FSUse iterators."""
        i = FSUseIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return FSUse.factory(self.policy, self.ocon)

cdef class GenfsconIterator:

    """Iterator for genfscon statements in the policy."""

    cdef:
        sepol.genfs_t *head
        sepol.genfs_t *curr
        object ocon_iter
        SELinuxPolicy policy

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.genfs_t *head):
        """Factory function for creating genfscon iterators."""
        i = GenfsconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

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
        self.ocon_iter = GenfsconOcontextIterator.factory(self.policy, self.curr.head,
                                                          intern(self.curr.fstype))

        self.curr = self.curr.next
        return self.ocon_iter.__next__()

    def __len__(self):
        cdef:
            size_t count = 0
            sepol.genfs_t *genfs = self.head

        while genfs:
            count += len(GenfsconOcontextIterator.factory(self.policy, genfs.head, genfs.fstype))
            genfs = genfs.next

        return count


cdef class GenfsconOcontextIterator(OcontextIterator):

    """Sub-iterator for genfscon statements."""

    cdef str fs

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head, fstype):
        """Factory function for creating genfscon sub-iterators."""
        i = GenfsconOcontextIterator()
        i.policy = policy
        i.head = i.curr = head
        i.fs = fstype
        return i

    def __next__(self):
        super().__next__()
        return Genfscon.factory(self.policy, self.ocon, self.fs)
