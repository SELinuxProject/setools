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
from itertools import chain

from . import qpol

# The libqpol SWIG class is not quite natural for
# Python the policy is repeatedly referenced in the
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
    # Policy properties
    #

    @property
    def handle_unknown(self):
        """The handle unknown permissions setting (allow,deny,reject)"""
        return self.policy.handle_unknown()

    @property
    def mls(self):
        """(T/F) The policy has MLS enabled."""
        return bool(self.policy.capability(qpol.QPOL_CAP_MLS))

    @property
    def version(self):
        """The policy database version (e.g. v29)"""
        return self.policy.version()

    #
    # Policy statistics
    #

    @property
    def allow_count(self):
        """The number of (type) allow rules."""
        return self.policy.avrule_allow_count()

    @property
    def attribute_count(self):
        """The number of (type) attributes."""
        return sum(1 for _ in self.attributes())

    @property
    def auditallow_count(self):
        """The number of auditallow rules."""
        return self.policy.avrule_auditallow_count()

    @property
    def boolean_count(self):
        """The number of Booleans."""
        return self.policy.bool_count()

    @property
    def category_count(self):
        """The number of categories."""
        return self.policy.cat_count()

    @property
    def class_count(self):
        """The number of object classes."""
        return self.policy.class_count()

    @property
    def common_count(self):
        """The number of common permission sets."""
        return self.policy.common_count()

    @property
    def conditional_count(self):
        """The number of conditionals."""
        return self.policy.cond_count()

    @property
    def constraint_count(self):
        """The number of standard constraints."""
        return sum(1 for _ in self.constraints())

    @property
    def dontaudit_count(self):
        """The number of dontaudit rules."""
        return self.policy.avrule_dontaudit_count()

    @property
    def fs_use_count(self):
        """fs_use_* statements."""
        return self.policy.fs_use_count()

    @property
    def genfscon_count(self):
        """The number of genfscon statements."""
        return self.policy.genfscon_count()

    @property
    def initialsids_count(self):
        """The number of initial sid statements."""
        return self.policy.isid_count()

    @property
    def level_count(self):
        """The number of levels."""
        return self.policy.level_count()

    @property
    def mlsconstraint_count(self):
        """The number of MLS constraints."""
        return sum(1 for _ in self.mlsconstraints())

    @property
    def mlsvalidatetrans_count(self):
        """The number of MLS validatetrans."""
        return sum(1 for _ in self.mlsvalidatetrans())

    @property
    def netifcon_count(self):
        """The number of netifcon statements."""
        return self.policy.netifcon_count()

    @property
    def neverallow_count(self):
        """The number of neverallow rules."""
        return self.policy.avrule_neverallow_count()

    @property
    def nodecon_count(self):
        """The number of nodecon statements."""
        return self.policy.nodecon_count()

    @property
    def permission_count(self):
        """The number of permissions."""
        return sum(len(c.perms) for c in chain(self.commons(), self.classes()))

    @property
    def permissives_count(self):
        """The number of permissive types."""
        return self.policy.permissive_count()

    @property
    def polcap_count(self):
        """The number of policy capabilities."""
        return self.policy.polcap_count()

    @property
    def portcon_count(self):
        """The number of portcon statements."""
        return self.policy.portcon_count()

    @property
    def range_transition_count(self):
        """The number of range_transition rules."""
        return self.policy.range_trans_count()

    @property
    def role_count(self):
        """The number of roles."""
        return self.policy.role_count()

    @property
    def role_allow_count(self):
        """The number of (role) allow rules."""
        return self.policy.role_allow_count()

    @property
    def role_transition_count(self):
        """The number of role_transition rules."""
        return self.policy.role_trans_count()

    @property
    def type_count(self):
        """The number of types."""
        return sum(1 for _ in self.types())

    @property
    def type_change_count(self):
        """The number of type_change rules."""
        return self.policy.terule_change_count()

    @property
    def type_member_count(self):
        """The number of type_member rules."""
        return self.policy.terule_member_count()

    @property
    def type_transition_count(self):
        """The number of type_transition rules."""
        return self.policy.terule_trans_count() + self.policy.filename_trans_count()

    @property
    def user_count(self):
        """The number of users."""
        return self.policy.user_count()

    @property
    def validatetrans_count(self):
        """The number of validatetrans."""
        return sum(1 for _ in self.validatetrans())

    #
    # Policy components lookup functions
    #

    def lookup_role(self, name):
        """Look up a role by name."""
        return role.role_factory(self.policy, name)

    def lookup_type(self, name):
        """Look up a type by name."""
        return typeattr.typeattr_factory(self.policy, name)

    def lookup_user(self, name):
        """Look up a user by name."""
        return user.user_factory(self.policy, name)

    #
    # Policy components generators
    #

    def attributes(self):
        """Generator which yields all (type) attributes."""

        # libqpol unfortunately iterates over attributes and aliases
        for type_ in self.policy.type_iter():
            t = typeattr.TypeAttr(self.policy, type_)
            if t.isattr:
                yield t

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

    def mlsvalidatetrans(self):
        """Generator which yields all mlsvalidatetrans."""

        for validatetrans in self.policy.validatetrans_iter():
            v = constraint.ValidateTrans(self.policy, validatetrans)
            if v.ismls:
                yield v

    def validatetrans(self):
        """Generator which yields all validatetrans."""

        for validatetrans in self.policy.validatetrans_iter():
            v = constraint.ValidateTrans(self.policy, validatetrans)
            if not v.ismls:
                yield v

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
