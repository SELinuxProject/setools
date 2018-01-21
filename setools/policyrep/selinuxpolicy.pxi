# Copyright 2014-2016, Tresys Technology, LLC
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
# pylint: disable=too-many-public-methods

import logging


try:
    import selinux
except ImportError:
    pass


class PolicyTarget(PolicyEnum):

    """Enumeration of policy targets."""

    selinux = sepol.SEPOL_TARGET_SELINUX
    xen = sepol.SEPOL_TARGET_XEN


class HandleUnknown(PolicyEnum):

    """Enumeration of handle unknown settings."""

    deny = sepol.SEPOL_DENY_UNKNOWN
    allow = sepol.SEPOL_ALLOW_UNKNOWN
    reject = sepol.SEPOL_REJECT_UNKNOWN


cdef void qpol_log_callback(void *varg, const qpol_policy_t *p, int level, const char *msg):
    """Logging callback for libqpol C functions."""
    logging.getLogger(__name__).debug(msg)


cdef class SELinuxPolicy:
    cdef:
        qpol_policy_t *handle
        readonly str path
        object log

    def __init__(self, policyfile=None):
        """
        Parameter:
        policyfile  Path to a policy to open.
        """

        self.log = logging.getLogger(__name__)

        if policyfile:
            self._load_policy(policyfile)
        else:
            try:
                self._load_running_policy()
            except NameError:
                raise RuntimeError("Loading the running policy requires libselinux Python bindings")

    def __dealloc__(self):
        if self.handle:
            qpol_policy_destroy(&self.handle)

    def __repr__(self):
        return "<SELinuxPolicy(\"{0}\")>".format(self.path)

    def __str__(self):
        return self.path

    def __deepcopy__(self, memo):
        # shallow copy as all of the members are immutable
        cdef SELinuxPolicy newobj
        newobj = SELinuxPolicy.__new__()
        newobj.handle = self.handle
        newobj.path = self.path
        newobj.log = self.log
        memo[id(self)] = newobj
        return newobj

    def __getstate__(self):
        return (self.policy, self.path, self.log, self._pickle())

    def __setstate__(self, state):
        self.policy = state[0]
        self.path = state[1]
        self.log = state[2]
        self._unpickle(state[3])

    cdef bytes _pickle(self):
        return <bytes>(<char *>self.handle)

    cdef _unpickle(self, bytes handle):
        memcpy(&self.handle, <char *>handle, sizeof(qpol_policy_t*))


    #
    # Policy loading functions
    #

    def _load_policy(self, str filename):
        """Load the specified policy."""
        self.log.info("Opening SELinux policy \"{0}\"".format(filename))

        if qpol_policy_open_from_file(filename, &self.handle, qpol_log_callback, NULL, 0) < 0:
            if (errno == EINVAL):
                raise InvalidPolicy("Invalid policy: {}. A binary policy must be specified. "
                                    "(use e.g. policy.{} or sepolicy) Source policies are not "
                                    "supported.".format(filename, sepol.POLICYDB_VERSION_MAX))
            else:
                raise OSError("Unable to open policy: {}: {}".format(filename, strerror(errno)))

        self.log.info("Successfully opened SELinux policy \"{0}\"".format(filename))
        self.path = filename

    def _potential_policies(self):
        """Generate a list of potential policies to use."""
        # try libselinux for current policy
        if selinux.selinuxfs_exists():
            yield selinux.selinux_current_policy_path()

        # otherwise look through the supported policy versions
        base_policy_path = selinux.selinux_binary_policy_path()
        for version in range(sepol.POLICYDB_VERSION_MAX, sepol.POLICYDB_VERSION_MIN-1, -1):
            yield "{0}.{1}".format(base_policy_path, version)

    def _load_running_policy(self):
        """Try to load the current running policy."""
        self.log.info("Attempting to locate current running policy.")

        for filename in self._potential_policies():
            try:
                self._load_policy(filename)
            except OSError as err:
                if err.errno != ENOENT:
                    raise
            else:
                break
        else:
            raise RuntimeError("Unable to locate an SELinux policy to load.")

    #
    # Policy properties
    #

    @property
    def handle_unknown(self):
        """The handle unknown permissions setting (allow,deny,reject)"""
        cdef unsigned int h
        qpol_policy_get_policy_handle_unknown(self.handle, &h)
        return HandleUnknown(h)

    @property
    def mls(self):
        """(T/F) The policy has MLS enabled."""
        return <bint> qpol_policy_has_capability(self.handle, QPOL_CAP_MLS)

    @property
    def target_platform(self):
        """The policy platform (selinux or xen)"""
        cdef int t
        qpol_policy_get_target_platform(self.handle, &t)
        return PolicyTarget(t)

    @property
    def version(self):
        """The policy database version (e.g. 29)"""
        cdef unsigned int v
        qpol_policy_get_policy_version(self.handle, &v)
        return v


    #
    # Policy statistics
    #
    @property
    def allow_count(self):
        """The number of (type) allow rules."""
        return sum(1 for r in self.terules()
                   if r.ruletype == TERuletype.allow)

    @property
    def allowxperm_count(self):
        """The number of allowxperm rules."""
        return sum(1 for r in self.terules()
                   if r.ruletype == TERuletype.allowxperm)

    @property
    def auditallow_count(self):
        """The number of auditallow rules."""
        return sum(1 for r in self.terules()
                   if r.ruletype == TERuletype.auditallow)

    @property
    def auditallowxperm_count(self):
        """The number of auditallowxperm rules."""
        return sum(1 for r in self.terules()
                   if r.ruletype == TERuletype.auditallowxperm)

    @property
    def boolean_count(self):
        """The number of Booleans."""
        return self.bools().size()

    @property
    def category_count(self):
        """The number of categories."""
        return sum(1 for _ in self.categories())

    @property
    def class_count(self):
        """The number of object classes."""
        return self.classes().size()

    @property
    def common_count(self):
        """The number of common permission sets."""
        return self.commons().size()

    @property
    def conditional_count(self):
        """The number of conditionals."""
        return self.conditionals().size()

    @property
    def constraint_count(self):
        """The number of standard constraints."""
        return sum(1 for c in self.constraints()
                   if c.ruletype == ConstraintRuletype.constrain)

    @property
    def default_count(self):
        """The number of default_* rules."""
        return sum(1 for d in self.defaults())

    @property
    def devicetreecon_count(self):
        """The number of Xen devicetreecon statements."""
        return self.devicetreecons().size()

    @property
    def dontaudit_count(self):
        """The number of dontaudit rules."""
        return sum(1 for r in self.terules()
                   if r.ruletype == TERuletype.dontaudit)

    @property
    def dontauditxperm_count(self):
        """The number of dontauditxperm rules."""
        return sum(1 for r in self.terules()
                   if r.ruletype == TERuletype.dontauditxperm)

    @property
    def fs_use_count(self):
        """The number of fs_use_* statements."""
        return self.fs_uses().size()

    @property
    def genfscon_count(self):
        """The number of genfscon statements."""
        return self.genfscons().size()

    @property
    def initialsids_count(self):
        """The number of initial sid statements."""
        return self.initialsids().size()

    @property
    def iomemcon_count(self):
        """The number of Xen iomemcon statements."""
        return self.iomemcons().size()

    @property
    def ioportcon_count(self):
        """The number of Xen ioportcon statements."""
        return self.ioportcons().size()

    @property
    def level_count(self):
        """The number of levels."""
        return sum(1 for _ in self.levels())

    @property
    def mlsconstraint_count(self):
        """The number of MLS constraints."""
        return sum(1 for c in self.constraints()
                   if c.ruletype == ConstraintRuletype.mlsconstrain)

    @property
    def mlsvalidatetrans_count(self):
        """The number of MLS validatetrans."""
        return sum(1 for v in self.constraints()
                   if v.ruletype == ConstraintRuletype.mlsvalidatetrans)

    @property
    def netifcon_count(self):
        """The number of netifcon statements."""
        return self.netifcons().size()

    @property
    def neverallow_count(self):
        """The number of neverallow rules."""
        return sum(1 for r in self.terules()
                   if r.ruletype == TERuletype.neverallow)

    @property
    def neverallowxperm_count(self):
        """The number of neverallowxperm rules."""
        return sum(1 for r in self.terules()
                   if r.ruletype == TERuletype.neverallowxperm)

    @property
    def nodecon_count(self):
        """The number of nodecon statements."""
        return self.nodecons().size()

    @property
    def pcidevicecon_count(self):
        """The number of Xen pcidevicecon statements."""
        return self.pcidevicecons().size()

    @property
    def permission_count(self):
        """The number of permissions."""
        return sum(len(c.perms) for c in chain(self.commons(), self.classes()))

    @property
    def permissives_count(self):
        """The number of permissive types."""
        return sum(1 for t in self.types() if t.ispermissive)

    @property
    def pirqcon_count(self):
        """The number of Xen pirqcon statements."""
        return self.pirqcons().size()

    @property
    def polcap_count(self):
        """The number of policy capabilities."""
        return self.polcaps().size()

    @property
    def portcon_count(self):
        """The number of portcon statements."""
        return self.portcons().size()

    @property
    def role_allow_count(self):
        """The number of role allow rules."""
        return sum(1 for r in self.rbacrules()
                   if r.ruletype == RBACRuletype.allow)

    @property
    def role_transition_count(self):
        """The number of role_transition rules."""
        return sum(1 for r in self.rbacrules()
                   if r.ruletype == RBACRuletype.role_transition)

    @property
    def range_transition_count(self):
        return sum(1 for r in self.mlsrules()
                   if r.ruletype == MLSRuletype.range_transition)

    @property
    def role_count(self):
        """The number of roles."""
        return self.roles().size()

    @property
    def type_attribute_count(self):
        """The number of (type) attributes."""
        return sum(1 for _ in self.typeattributes())

    @property
    def type_change_count(self):
        """The number of type_change rules."""
        return sum(1 for r in self.terules()
                   if r.ruletype == TERuletype.type_change)

    @property
    def type_count(self):
        """The number of types."""
        return sum(1 for _ in self.types())

    @property
    def type_member_count(self):
        """The number of type_member rules."""
        return sum(1 for r in self.terules()
                   if r.ruletype == TERuletype.type_member)

    @property
    def type_transition_count(self):
        """The number of type_transition rules."""
        return sum(1 for r in self.terules()
                   if r.ruletype == TERuletype.type_transition)

    @property
    def typebounds_count(self):
        """The number of typebounds rules."""
        return sum(1 for b in self.bounds()
                   if b.ruletype == BoundsRuletype.typebounds)

    @property
    def user_count(self):
        return self.users().size()

    @property
    def validatetrans_count(self):
        """The number of validatetrans."""
        return sum(1 for v in self.constraints()
                   if v.ruletype == ConstraintRuletype.validatetrans)

    #
    # Policy components lookup functions
    #
    def lookup_boolean(self, name):
        """Look up a Boolean."""
        return boolean_factory_lookup(self, name)

    def lookup_class(self, name):
        """Look up an object class."""
        return class_factory_lookup(self, name)

    def lookup_common(self, name):
        """Look up a common permission set."""
        return common_factory_lookup(self, name)

    def lookup_initialsid(self, name):
        """Look up an initial sid."""
        return initialsid_factory_lookup(self, name)

    def lookup_level(self, level):
        """Look up a MLS level."""
        return level_factory_lookup(self, level)

    def lookup_sensitivity(self, name):
        """Look up a MLS sensitivity by name."""
        return sensitivity_factory_lookup(self, name)

    def lookup_range(self, range_):
        """Look up a MLS range."""
        return range_factory_lookup(self, range_)

    def lookup_role(self, name):
        """Look up a role by name."""
        return role_factory_lookup(self, name)

    def lookup_type(self, name):
        """Look up a type by name."""
        return type_factory_lookup(self, name, True)

    def lookup_type_or_attr(self, name):
        """Look up a type or type attribute by name."""
        return type_or_attr_factory_lookup(self, name, True)

    def lookup_typeattr(self, name):
        """Look up a type attribute by name."""
        return attribute_factory_lookup(self, name)

    def lookup_user(self, name):
        """Look up a user by name."""
        return user_factory_lookup(self, name)

    #
    # Policy components iterators
    #
    def bools(self):
        """Iterator which yields all Booleans."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_bool_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, boolean_factory_iter)

    def bounds(self):
        """Iterator which yields all *bounds statements (typebounds, etc.)"""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_typebounds_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, bounds_factory_iter)

    def categories(self):
        """Iterator which yields all MLS categories."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_cat_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, category_factory_iter, ValueError)

    def classes(self):
        """Iterator which yields all object classes."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_class_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, class_factory_iter)

    def commons(self):
        """Iterator which yields all commons."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_common_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, common_factory_iter)

    def defaults(self):
        """Iterator over all default_* statements."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_default_object_iter(self.handle, &iter):
            raise MemoryError

        return default_iterator_factory(self, iter)

    def levels(self):
        """Iterator which yields all level declarations."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_level_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, level_decl_factory_iter, ValueError)

    def polcaps(self):
        """Iterator which yields all policy capabilities."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_polcap_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, polcap_factory_iter)

    def roles(self):
        """Iterator which yields all roles."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_role_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, role_factory_iter)

    def sensitivities(self):
        """Iterator over all sensitivities."""
        # see mls.pxi for more info on why level_iter is used here.
        cdef qpol_iterator_t *iter
        if qpol_policy_get_level_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, sensitivity_factory_iter, ValueError)

    def types(self):
        """Iterator over all types."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_type_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, type_factory_iter, ValueError)

    def typeattributes(self):
        """Iterator over all (type) attributes."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_type_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, attribute_factory_iter, ValueError)

    def users(self):
        """Iterator which yields all roles."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_user_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, user_factory_iter)

    #
    # Policy rules iterators
    #
    def conditionals(self):
        """Iterator over all conditional rule blocks."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_cond_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, conditional_factory_iter)

    def mlsrules(self):
        """Iterator over all MLS rules."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_range_trans_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, mls_rule_factory_iter)

    def rbacrules(self):
        """Iterator over all RBAC rules."""
        cdef qpol_iterator_t *ra_iter
        if qpol_policy_get_role_allow_iter(self.handle, &ra_iter):
            raise MemoryError

        cdef qpol_iterator_t *rt_iter
        if qpol_policy_get_role_trans_iter(self.handle, &rt_iter):
            raise MemoryError

        return chain(qpol_iterator_factory(self, ra_iter, role_allow_factory_iter),
                     qpol_iterator_factory(self, rt_iter, role_trans_factory_iter))

    def terules(self):
        """Iterator over all type enforcement rules."""
        cdef qpol_iterator_t *av_iter
        cdef qpol_iterator_t *te_iter
        cdef qpol_iterator_t *ft_iter

        cdef uint32_t av_rule_types = QPOL_RULE_ALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT \
            | QPOL_RULE_XPERMS_ALLOW | QPOL_RULE_XPERMS_AUDITALLOW | QPOL_RULE_XPERMS_DONTAUDIT

        cdef uint32_t te_rule_types = QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER

        if qpol_policy_has_capability(self.handle, QPOL_CAP_NEVERALLOW):
            av_rule_types |= QPOL_RULE_NEVERALLOW | QPOL_RULE_XPERMS_NEVERALLOW

        if qpol_policy_get_avrule_iter(self.handle, av_rule_types, &av_iter):
            raise MemoryError

        if qpol_policy_get_terule_iter(self.handle, te_rule_types, &te_iter):
            raise MemoryError

        if qpol_policy_get_filename_trans_iter(self.handle, &ft_iter):
            raise MemoryError

        return chain(qpol_iterator_factory(self, av_iter, avrule_factory_iter),
                     qpol_iterator_factory(self, te_iter, terule_factory_iter),
                     qpol_iterator_factory(self, ft_iter, filename_terule_factory_iter))

    #
    # Constraints iterators
    #
    def constraints(self):
        """Iterator over all constraints (regular and MLS)."""
        cdef qpol_iterator_t *c_iter
        if qpol_policy_get_constraint_iter(self.handle, &c_iter):
            raise MemoryError

        cdef qpol_iterator_t *v_iter
        if qpol_policy_get_validatetrans_iter(self.handle, &v_iter):
            raise MemoryError

        return chain(qpol_iterator_factory(self, c_iter, constraint_factory_iter),
                     qpol_iterator_factory(self, v_iter, validatetrans_factory_iter))

    #
    # In-policy Labeling statement iterators
    #
    def fs_uses(self):
        """Iterator over all fs_use_* statements."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_fs_use_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, fs_use_factory_iter)

    def genfscons(self):
        """Iterator over all genfscon statements."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_genfscon_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, genfscon_factory_iter)

    def initialsids(self):
        """Iterator over all initial SID statements."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_isid_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, initialsid_factory_iter)

    def netifcons(self):
        """Iterator over all netifcon statements."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_netifcon_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, netifcon_factory_iter)

    def nodecons(self):
        """Iterator over all nodecon statements."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_nodecon_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, nodecon_factory_iter)

    def portcons(self):
        """Iterator over all portcon statements."""
        cdef qpol_iterator_t *iter
        if qpol_policy_get_portcon_iter(self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self, iter, portcon_factory_iter)

    #
    # Xen labeling iterators
    #
    def devicetreecons(self):
        """Iterator over all devicetreecon statements."""
        return devicetreecon_iterator_factory(self,
                                              self.handle.p.p.ocontexts[sepol.OCON_XEN_DEVICETREE])

    def iomemcons(self):
        """Iterator over all iomemcon statements."""
        return iomemcon_iterator_factory(self, self.handle.p.p.ocontexts[sepol.OCON_XEN_IOMEM])

    def ioportcons(self):
        """Iterator over all ioportcon statements."""
        return ioportcon_iterator_factory(self, self.handle.p.p.ocontexts[sepol.OCON_XEN_IOPORT])

    def pcidevicecons(self):
        """Iterator over all pcidevicecon statements."""
        return pcidevicecon_iterator_factory(self,
                                             self.handle.p.p.ocontexts[sepol.OCON_XEN_PCIDEVICE])

    def pirqcons(self):
        """Iterator over all pirqcon statements."""
        return pirqcon_iterator_factory(self, self.handle.p.p.ocontexts[sepol.OCON_XEN_PIRQ])
