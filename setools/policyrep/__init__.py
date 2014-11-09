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
# Create a Python representation of the policy.
# The idea is that this is module provides convenient
# abstractions and methods for accessing the policy
# structures.

from . import qpol

# The libqpol SWIG class is not quite natural for
# Python, since void* are passed around from the
# generic C iterator implementation in libqpol
# (note the _from_void calls).  Additionally,
# the policy is repeatedly referenced in the
# function calls, which makes sense for C code
# but not for python code, so each object keeps
# a reference to the policy for internal use.
# This also makes sense since an object would only
# be valid for the policy it comes from.

# Components
from . import objclass
from . import typeattr
from . import boolcond
from . import role
from . import user
from . import mls
from . import polcap

# Rules
from . import terule
from . import rbacrule
from . import mlsrule

# Constraints
from . import constraint

# In-policy Labeling
from . import initsid
from . import fscontext
from . import netcontext


class SELinuxPolicy(object):

    """The complete SELinux policy."""

    def __init__(self, policyfile):
        """
        Parameter:
        policyfile  Path to a policy to open.
        """

        try:
            self.policy = qpol.qpol_policy_t(policyfile, 0)
        except OSError as err:
            raise OSError(
                "Error opening policy file \"{0}\": {1}".format(policyfile, err))

    #
    # Policy components lookup functions
    #

    def lookup_type(self, name):
        """Look up a type by name."""
        return typeattr.TypeAttr(self.policy, name)

    #
    # Policy components generators
    #

    def classes(self):
        """Generator which yields all object classes."""

        for class_ in self.policy.class_iter():
            yield objclass.ObjClass(self.policy, class_)

    def commons(self):
        """Generator which yields all commons."""

        for common in self.policy.common_iter():
            yield objclass.Common(self.policy, common)

    def types(self):
        """Generator which yields all types."""

        # libqpol unfortunately iterates over attributes and aliases
        for type_ in self.policy.type_iter():
            t = typeattr.TypeAttr(self.policy, type_)
            if not t.isattr and not t.isalias:
                yield t

    def roles(self):
        """Generator which yields all roles."""

        for role_ in self.policy.role_iter():
            yield role.Role(self.policy, role_)

    def users(self):
        """Generator which yields all users."""

        for user_ in self.policy.user_iter():
            yield user.User(self.policy, user_)

    def bools(self):
        """Generator which yields all Booleans."""

        for bool_ in self.policy.bool_iter():
            yield boolcond.Boolean(self.policy, bool_)

    def polcaps(self):
        """Generator which yields all policy capabilities."""

        for cap in self.policy.polcap_iter():
            yield polcap.PolicyCapability(self.policy, cap)

    def permissives(self):
        """Generator which yields all permissive types."""

        for type_ in self.policy.permissive_iter():
            yield typeattr.TypeAttr(self.policy, type_)

    #
    # Policy rules generators
    #
    def terules(self):
        """Generator which yields all type enforcement rules."""

        for rule in self.policy.avrule_iter():
            yield terule.TERule(self.policy, rule)

        for rule in self.policy.terule_iter():
            yield terule.TERule(self.policy, rule)

        for rule in self.policy.filename_trans_iter():
            yield terule.TERule(self.policy, rule)

    def rbacrules(self):
        """Generator which yields all RBAC rules."""

        for rule in self.policy.role_allow_iter():
            yield rbacrule.RBACRule(self.policy, rule)

        for rule in self.policy.role_trans_iter():
            yield rbacrule.RBACRule(self.policy, rule)

    def mlsrules(self):
        """Generator which yields all MLS rules."""

        for rule in self.policy.range_trans_iter():
            yield mlsrule.MLSRule(self.policy, rule)

    #
    # Constraints generators
    #

    def constraints(self):
        """Generator which yields all constraints."""

        for constraint_ in self.policy.constraint_iter():
            c = constraint.Constraint(self.policy, constraint_)
            if not c.ismls:
                yield c

    def mlsconstraints(self):
        """Generator which yields all MLS constraints."""

        for constraint_ in self.policy.constraint_iter():
            c = constraint.Constraint(self.policy, constraint_)
            if c.ismls:
                yield c

    #
    # In-policy Labeling statement generators
    #
    def initialsids(self):
        """Generator which yields all initial SID statements."""

        for sid in self.policy.isid_iter():
            yield initsid.InitialSID(self.policy, sid)

    def fs_uses(self):
        """Generator which yields all fs_use_* statements."""

        for fs_use in self.policy.fs_use_iter():
            yield fscontext.FSUse(self.policy, fs_use)

    def genfscons(self):
        """Generator which yields all genfscon statements."""

        for fscon in self.policy.genfscon_iter():
            yield fscontext.Genfscon(self.policy, fscon)

    def netifcons(self):
        """Generator which yields all netifcon statements."""

        for ifcon in self.policy.netifcon_iter():
            yield netcontext.Netifcon(self.policy, ifcon)

    def nodecons(self):
        """Generator which yields all nodecon statements."""

        for node in self.policy.nodecon_iter():
            yield netcontext.Nodecon(self.policy, node)

    def portcons(self):
        """Generator which yields all portcon statements."""

        for port in self.policy.portcon_iter():
            yield netcontext.Portcon(self.policy, port)
