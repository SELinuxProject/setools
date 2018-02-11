# Copyright 2014, Tresys Technology, LLC
# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
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

cdef class InitialSID(Ocontext):

    """An initial SID statement."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext *symbol):
        """Factory function for creating InitialSID objects."""
        i = InitialSID()
        i.policy = policy
        i.handle = symbol
        return i

    def __str__(self):
        return intern(self.handle.u.name)


cdef class InitialSIDIterator(OcontextIterator):

    """Iterator for initial SID statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating initial SID iterators."""
        i = InitialSIDIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return InitialSID.factory(self.policy, self.ocon)
