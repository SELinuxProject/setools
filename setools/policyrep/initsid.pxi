# Copyright 2014, Tresys Technology, LLC
# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

#
# Constants
#
# Binary policy does not contain the SID names
SELINUX_SIDNAMES = ("undefined", "kernel", "security", "unlabeled", "fs", "file", "file_labels",
    "init", "any_socket", "port", "netif", "netmsg", "node", "igmp_packet", "icmp_socket",
    "tcp_socket", "sysctl_modprobe", "sysctl", "sysctl_fs", "sysctl_kernel", "sysctl_net",
    "sysctl_net_unix", "sysctl_vm", "sysctl_dev", "kmod", "policy", "scmp_packet", "devnull")


XEN_SIDNAMES = ("xen", "dom0", "domxen", "domio", "unlabeled", "security", "irq", "iomem", "ioport",
    "device", "domU", "domDM")


#
# Classes
#
cdef class InitialSID(Ocontext):

    """An initial SID statement."""

    cdef readonly str name

    @staticmethod
    cdef inline InitialSID factory(SELinuxPolicy policy, sepol.ocontext *symbol):
        """Factory function for creating InitialSID objects."""
        cdef InitialSID i = InitialSID.__new__(InitialSID)
        i.policy = policy
        i.key = <uintptr_t>symbol
        i.context = Context.factory(policy, symbol.context)

        if symbol.u.name:
            i.name = intern(symbol.u.name)
        elif policy.target_platform == PolicyTarget.selinux:
            i.name = SELINUX_SIDNAMES[<uint32_t>symbol.sid[0]]
        elif policy.target_platform == PolicyTarget.xen:
            i.name = XEN_SIDNAMES[<uint32_t>symbol.sid[0]]
        else:
            raise NotImplementedError

        return i

    def __str__(self):
        return self.name

    def statement(self):
        return "sid {0} {0.context}".format(self)


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
