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

import setools.qpol as qpol

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
import objclass
import typeattr
import boolcond
import role
import user
import mls
import polcap

# Rules
import terule
import rbacrule
import mlsrule

# Constraints
import constraint

# In-policy Labeling
import initsid
import fscontext
import netcontext


class SELinuxPolicy(object):

    """The complete SELinux policy."""

    def __init__(self, policyfile):
        """
        Parameter:
        policyfile	str	Path to a policy to open.
        """

        self.policy = qpol.qpol_policy_t(policyfile, 0)

        # libqpol's SWIG wrapper doesn't throw exceptions, so we don't
        # know what kind of error there was when opening the policy
        if not self.policy.this:
            raise RuntimeError(
                "Error opening policy file \"{0}\"".format(policyfile))

    #
    # Policy components generators
    #

    def classes(self):
        """Generator which yields all object classes."""

        qiter = self.policy.get_class_iter()
        while not qiter.end():
            yield objclass.ObjClass(self.policy, qpol.qpol_class_from_void(qiter.get_item()))
            qiter.next()

    def commons(self):
        """Generator which yields all commons."""

        qiter = self.policy.get_common_iter()
        while not qiter.end():
            yield objclass.Common(self.policy, qpol.qpol_common_from_void(qiter.get_item()))
            qiter.next()

    def types(self):
        """Generator which yields all types."""

        # libqpol unfortunately iterates over attributes and aliases
        qiter = self.policy.get_type_iter()
        while not qiter.end():
            t = typeattr.TypeAttr(
                self.policy, qpol.qpol_type_from_void(qiter.get_item()))
            if not t.isattr and not t.isalias:
                yield t
            qiter.next()

    def roles(self):
        """Generator which yields all roles."""

        qiter = self.policy.get_role_iter()
        while not qiter.end():
            yield role.Role(self.policy, qpol.qpol_role_from_void(qiter.get_item()))
            qiter.next()

    def users(self):
        """Generator which yields all users."""

        qiter = self.policy.get_user_iter()
        while not qiter.end():
            yield user.User(self.policy, qpol.qpol_user_from_void(qiter.get_item()))
            qiter.next()

    def bools(self):
        """Generator which yields all Booleans."""

        qiter = self.policy.get_bool_iter()
        while not qiter.end():
            yield boolcond.Boolean(self.policy, qpol.qpol_bool_from_void(qiter.get_item()))
            qiter.next()

    def polcaps(self):
        """Generator which yields all policy capabilities."""

        qiter = self.policy.get_polcap_iter()
        while not qiter.end():
            yield polcap.PolicyCapability(self.policy, qpol.qpol_polcap_from_void(qiter.get_item()))
            qiter.next()

    #
    # Policy rules generators
    #
    def terules(self):
        """Generator which yields all type enforcement rules."""

        av_ruletype = qpol.QPOL_RULE_ALLOW | qpol.QPOL_RULE_AUDITALLOW | qpol.QPOL_RULE_DONTAUDIT
        te_ruletype = qpol.QPOL_RULE_TYPE_TRANS | qpol.QPOL_RULE_TYPE_CHANGE | qpol.QPOL_RULE_TYPE_MEMBER

        qiter = self.policy.get_avrule_iter(av_ruletype)
        while not qiter.end():
            yield terule.TERule(self.policy, qpol.qpol_avrule_from_void(qiter.get_item()))
            qiter.next()

        qiter = self.policy.get_terule_iter(te_ruletype)
        while not qiter.end():
            yield terule.TERule(self.policy, qpol.qpol_terule_from_void(qiter.get_item()))
            qiter.next()

        qiter = self.policy.get_filename_trans_iter()
        while not qiter.end():
            yield terule.TERule(self.policy, qpol.qpol_filename_trans_from_void(qiter.get_item()))
            qiter.next()

    def rbacrules(self):
        """Generator which yields all RBAC rules."""

        qiter = self.policy.get_role_allow_iter()
        while not qiter.end():
            yield rbacrule.RBACRule(self.policy, qpol.qpol_role_allow_from_void(qiter.get_item()))
            qiter.next()

        qiter = self.policy.get_role_trans_iter()
        while not qiter.end():
            yield rbacrule.RBACRule(self.policy, qpol.qpol_role_trans_from_void(qiter.get_item()))
            qiter.next()

    def mlsrules(self):
        """Generator which yields all MLS rules."""

        qiter = self.policy.get_range_trans_iter()
        while not qiter.end():
            yield mlsrule.MLSRule(self.policy, qpol.qpol_range_trans_from_void(qiter.get_item()))
            qiter.next()

    #
    # Constraints generators
    #

    def constraints(self):
        """Generator which yields all constraints."""

        qiter = self.policy.get_constraint_iter()
        while not qiter.end():
            c = constraint.Constraint(self.policy, qpol.qpol_constraint_from_void(qiter.get_item()))
            if not c.ismls:
                yield c
            qiter.next()

    def mlsconstraints(self):
        """Generator which yields all MLS constraints."""

        qiter = self.policy.get_constraint_iter()
        while not qiter.end():
            c = constraint.Constraint(self.policy, qpol.qpol_constraint_from_void(qiter.get_item()))
            if c.ismls:
                yield c
            qiter.next()

    #
    # In-policy Labeling statement generators
    #
    def initialsids(self):
        """Generator which yields all initial SID statements."""

        qiter = self.policy.get_isid_iter()
        while not qiter.end():
            yield initsid.InitialSID(self.policy, qpol.qpol_isid_from_void(qiter.get_item()))
            qiter.next()

    def fs_uses(self):
        """Generator which yields all fs_use_* statements."""

        qiter = self.policy.get_fs_use_iter()
        while not qiter.end():
            yield fscontext.FSUse(self.policy, qpol.qpol_fs_use_from_void(qiter.get_item()))
            qiter.next()

    def genfscons(self):
        """Generator which yields all genfscon statements."""

        qiter = self.policy.get_genfscon_iter()
        while not qiter.end():
            yield fscontext.Genfscon(self.policy, qpol.qpol_genfscon_from_void(qiter.get_item()))
            qiter.next()

    def netifcons(self):
        """Generator which yields all netifcon statements."""

        qiter = self.policy.get_netifcon_iter()
        while not qiter.end():
            yield netcontext.Netifcon(self.policy, qpol.qpol_netifcon_from_void(qiter.get_item()))
            qiter.next()

    def nodecons(self):
        """Generator which yields all nodecon statements."""

        qiter = self.policy.get_nodecon_iter()
        while not qiter.end():
            yield netcontext.Nodecon(self.policy, qpol.qpol_nodecon_from_void(qiter.get_item()))
            qiter.next()

    def portcons(self):
        """Generator which yields all portcon statements."""

        qiter = self.policy.get_portcon_iter()
        while not qiter.end():
            yield netcontext.Portcon(self.policy, qpol.qpol_portcon_from_void(qiter.get_item()))
            qiter.next()
