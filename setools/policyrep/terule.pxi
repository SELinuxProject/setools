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
import itertools

#
# AV rule factory functions
#
cdef inline AVRule avrule_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over AVRule objects."""
    cdef const qpol_avrule_t *rule = <const qpol_avrule_t *> symbol.obj
    cdef uint32_t extended

    if qpol_avrule_get_is_extended(policy.handle, rule, &extended):
        ex = LowLevelPolicyError("Error determining if av rule is extended: {}".format(
                                 strerror(errno)))
        ex.errno = errno
        raise ex

    if extended:
        return avrulex_factory(policy, rule)
    else:
        return avrule_factory(policy, rule)


cdef inline AVRule avrule_factory(SELinuxPolicy policy, const qpol_avrule_t *symbol):
    """Factory function for creating AVRule objects."""
    r = AVRule()
    r.policy = policy
    r.handle = symbol
    return r


cdef inline AVRuleXperm avrulex_factory(SELinuxPolicy policy, const qpol_avrule_t *symbol):
    """Factory function for creating AVRuleXperm objects."""
    r = AVRuleXperm()
    r.policy = policy
    r.handle = symbol
    return r

#
# TE rule factory functions
#
cdef inline TERule terule_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over TERule objects."""
    return terule_factory(policy, <const qpol_terule_t *> symbol.obj)


cdef inline TERule terule_factory(SELinuxPolicy policy, const qpol_terule_t *symbol):
    """Factory function for creating TERule objects."""
    r = TERule()
    r.policy = policy
    r.handle = symbol
    return r

#
# Extended permission set iterator factory function
#
cdef inline int xperms_factory_iter(SELinuxPolicy _, QpolIteratorItem item):
        cdef int *obj = <int *>item.obj
        cdef int i = obj[0]

        # The library allocates integers while reading out the bitmap
        free(item.obj)

        return i


#
# Expanded TE rule factory functions
#
cdef expanded_avrule_factory(AVRule original, source, target):
    """Factory function for creating ExpandedAVRule objects."""
    if original.extended:
        r = ExpandedAVRuleXperm()
    else:
        r = ExpandedAVRule()

    r.policy = original.policy
    r.handle = original.handle
    r.source = source
    r.target = target
    r.origin = original
    r.perms = original.perms
    return r


cdef expanded_terule_factory(TERule original, source, target):
    """Factory function for creating ExpandedTERule objects."""
    r = ExpandedTERule()
    r.policy = original.policy
    r.handle = original.handle
    r.source = source
    r.target = target
    r.origin = original
    return r


cdef expanded_filename_terule_factory(FileNameTERule original, source, target):
    """Factory function for creating ExpandedTERule objects."""
    r = ExpandedFileNameTERule()
    r.policy = original.policy
    r.handle = original.handle
    r.source = source
    r.target = target
    r.origin = original
    return r


#
# Classes
#
class TERuletype(PolicyEnum):

    """Enumeration of types of TE rules."""

    allow = QPOL_RULE_ALLOW
    neverallow = QPOL_RULE_NEVERALLOW
    auditallow = QPOL_RULE_AUDITALLOW
    dontaudit = QPOL_RULE_DONTAUDIT
    allowxperm = QPOL_RULE_XPERMS_ALLOW
    neverallowxperm = QPOL_RULE_XPERMS_NEVERALLOW
    auditallowxperm = QPOL_RULE_XPERMS_AUDITALLOW
    dontauditxperm = QPOL_RULE_XPERMS_DONTAUDIT
    type_transition = QPOL_RULE_TYPE_TRANS
    type_change = QPOL_RULE_TYPE_CHANGE
    type_member = QPOL_RULE_TYPE_MEMBER


cdef class AVRule(PolicyRule):

    """An access vector type enforcement rule."""

    cdef const qpol_avrule_t *handle

    def __str__(self):
        rule_string = "{0.ruletype} {0.source} {0.target}:{0.tclass} ".format(self)

        # allow/dontaudit/auditallow/neverallow rules
        perms = self.perms
        if len(perms) > 1:
            rule_string += "{{ {0} }};".format(' '.join(sorted(perms)))
        else:
            # convert to list since sets cannot be indexed
            rule_string += "{0};".format(list(perms)[0])

        try:
            rule_string += " [ {0.conditional} ]:{0.conditional_block}".format(self)
        except RuleNotConditional:
            pass

        return rule_string

    def __hash__(self):
        try:
            cond = self.conditional
            cond_block = self.conditional_block
        except RuleNotConditional:
            cond = None
            cond_block = None

        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{1}|{2}".format(
            self, cond, cond_block))

    def __lt__(self, other):
        return str(self) < str(other)

    def __deepcopy__(self, memo):
        # shallow copy as all of the members are immutable
        newobj = avrule_factory(self.policy, self.handle)
        memo[id(self)] = newobj
        return newobj

    def __getstate__(self):
        return (self.policy, self._pickle())

    def __setstate__(self, state):
        self.policy = state[0]
        self._unpickle(state[1])

    cdef bytes _pickle(self):
        return <bytes>(<char *>self.handle)

    cdef _unpickle(self, bytes handle):
        memcpy(&self.handle, <char *>handle, sizeof(qpol_avrule_t*))

    def _eq(self, AVRule other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def ruletype(self):
        """The rule type."""
        cdef uint32_t rt
        if qpol_avrule_get_rule_type(self.policy.handle, self.handle, &rt):
            ex = LowLevelPolicyError("Error reading rule type for AV rule: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return TERuletype(rt)

    @property
    def source(self):
        """The rule's source type/attribute."""
        cdef const qpol_type_t *t
        if qpol_avrule_get_source_type(self.policy.handle, self.handle, &t):
            ex = LowLevelPolicyError("Error reading source type/attr for AV rule: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return type_or_attr_factory(self.policy, <sepol.type_datum_t *> t)

    @property
    def target(self):
        """The rule's target type/attribute."""
        cdef const qpol_type_t *t
        if qpol_avrule_get_target_type(self.policy.handle, self.handle, &t):
            ex = LowLevelPolicyError("Error reading target type/attr for AV rule: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return type_or_attr_factory(self.policy, <sepol.type_datum_t *> t)

    @property
    def tclass(self):
        """The rule's object class."""
        return ObjClass.factory(self.policy, self.policy.handle.p.p.class_val_to_struct[(<sepol.avtab_ptr_t>self.handle).key.target_class - 1])

    @property
    def perms(self):
        """The rule's permission set."""
        cdef qpol_iterator_t *iter
        if qpol_avrule_get_perm_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return set(qpol_iterator_factory(self.policy, iter, string_factory_iter))

    @property
    def default(self):
        """The rule's default type."""
        raise RuleUseError("{0} rules do not have a default type.".format(self.ruletype))

    @property
    def filename(self):
        raise RuleUseError("{0} rules do not have file names".format(self.ruletype))

    @property
    def conditional(self):
        """The rule's conditional expression."""
        cdef const qpol_cond_t *c
        if qpol_avrule_get_cond(self.policy.handle, self.handle, &c):
            ex = LowLevelPolicyError("Error reading AV rule conditional: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        if c:
            return Conditional.factory(self.policy, <sepol.cond_node_t *>c)
        else:
            raise RuleNotConditional

    @property
    def conditional_block(self):
        """
        The conditional block of the rule (T/F)

        For example, if the policy looks like this:

        if ( the_conditional_expression ) {
            If the rule is here, this property is True
        } else {
            If the rule is here, this property is False
        }
        """
        cdef const qpol_cond_t *c
        cdef uint32_t which

        if qpol_avrule_get_cond(self.policy.handle, self.handle, &c):
            ex = LowLevelPolicyError("Error reading AV rule conditional: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        if not c:
            raise RuleNotConditional

        if qpol_avrule_get_which_list(self.policy.handle, self.handle, &which):
            ex = LowLevelPolicyError("Error reading AV rule conditional block: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return bool(which)

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        for s, t in itertools.product(self.source.expand(), self.target.expand()):
            yield expanded_avrule_factory(self, s, t)


cdef class IoctlSet(set):

    """
    A set with overridden string functions which compresses
    the output into ioctl ranges instead of individual elements.
    """

    def __format__(self, spec):
        """
        String formating.

        The standard formatting (no specification) will render the
        ranges of ioctls, space separated.

        The , option by itself will render the ranges of ioctls,
        comma separated

        Any other combination of formatting options will fall back
        to set's formatting behavior.
        """

        # generate short permission notation
        perms = sorted(self)
        shortlist = []
        for _, i in itertools.groupby(perms, key=lambda k, c=itertools.count(): k - next(c)):
            group = list(i)
            if len(group) > 1:
                shortlist.append("{0:#06x}-{1:#06x}".format(group[0], group[-1]))
            else:
                shortlist.append("{0:#06x}".format(group[0]))

        if not spec:
            return " ".join(shortlist)
        elif spec == ",":
            return ", ".join(shortlist)
        else:
            return super(IoctlSet, self).__format__(spec)

    def __str__(self):
        return "{0}".format(self)

    def __repr__(self):
        return "{{ {0:,} }}".format(self)

    def ranges(self):
        """
        Return the number of ranges in the set.  Main use
        is to determine if brackets need to be used in
        string output.
        """
        return sum(1 for (_a, _b) in itertools.groupby(
            sorted(self), key=lambda k, c=itertools.count(): k - next(c)))


cdef class AVRuleXperm(AVRule):

    """An extended permission access vector type enforcement rule."""

    def __init__(self):
        self.extended = True

    def __str__(self):
        rule_string = "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.xperm_type} ". \
                            format(self)

        # generate short permission notation
        perms = self.perms
        if perms.ranges() > 1:
            rule_string += "{{ {0} }};".format(perms)
        else:
            rule_string += "{0};".format(perms)

        return rule_string

    def __lt__(self, other):
        return str(self) < str(other)

    def __deepcopy__(self, memo):
        # shallow copy as all of the members are immutable
        newobj = avrulex_factory(self.policy, self.handle)
        memo[id(self)] = newobj
        return newobj

    def __getstate__(self):
        return (self.policy, self._pickle())

    def __setstate__(self, state):
        self.policy = state[0]
        self._unpickle(state[1])

    cdef bytes _pickle(self):
        return <bytes>(<char *>self.handle)

    cdef _unpickle(self, bytes handle):
        memcpy(&self.handle, <char *>handle, sizeof(qpol_avrule_t*))

    @property
    def perms(self):
        """The rule's extended permission set."""
        cdef qpol_iterator_t *iter
        if qpol_avrule_get_xperm_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return IoctlSet(qpol_iterator_factory(self.policy, iter, xperms_factory_iter))

    @property
    def xperm_type(self):
        """The standard permission extended by these permissions (e.g. ioctl)."""
        cdef char *xt
        if qpol_avrule_get_xperm_type(self.policy.handle, self.handle, &xt):
            raise ValueError("Could not get xperm type for av rule")

        return intern(xt)


cdef class TERule(PolicyRule):

    """A type_* type enforcement rule."""

    cdef const qpol_terule_t *handle

    def __str__(self):
        rule_string = "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default};".format(self)

        try:
            rule_string += " [ {0.conditional} ]:{0.conditional_block}".format(self)
        except RuleNotConditional:
            pass

        return rule_string

    def __hash__(self):
        try:
            cond = self.conditional
            cond_block = self.conditional_block
        except RuleNotConditional:
            cond = None
            cond_block = None

        try:
            filename = self.filename
        except (TERuleNoFilename, RuleUseError):
            filename = None

        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{1}|{2}|{3}".format(
            self, filename, cond, cond_block))

    def __lt__(self, other):
        return str(self) < str(other)

    def __deepcopy__(self, memo):
        # shallow copy as all of the members are immutable
        newobj = terule_factory(self.policy, self.handle)
        memo[id(self)] = newobj
        return newobj

    def __getstate__(self):
        return (self.policy, self._pickle())

    def __setstate__(self, state):
        self.policy = state[0]
        self._unpickle(state[1])

    cdef bytes _pickle(self):
        return <bytes>(<char *>self.handle)

    cdef _unpickle(self, bytes handle):
        memcpy(&self.handle, <char *>handle, sizeof(qpol_terule_t*))

    def _eq(self, TERule other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def ruletype(self):
        """The rule type."""
        cdef uint32_t rt
        if qpol_terule_get_rule_type(self.policy.handle, self.handle, &rt):
            ex = LowLevelPolicyError("Error reading rule type for TE rule: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return TERuletype(rt)

    @property
    def source(self):
        """The rule's source type/attribute."""
        cdef const qpol_type_t *t
        if qpol_terule_get_source_type(self.policy.handle, self.handle, &t):
            ex = LowLevelPolicyError("Error reading source type/attr for TE rule: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return type_or_attr_factory(self.policy, <sepol.type_datum_t *>t)

    @property
    def target(self):
        """The rule's target type/attribute."""
        cdef const qpol_type_t *t
        if qpol_terule_get_target_type(self.policy.handle, self.handle, &t):
            ex = LowLevelPolicyError("Error reading target type/attr for TE rule: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return type_or_attr_factory(self.policy, <sepol.type_datum_t *>t)

    @property
    def tclass(self):
        """The rule's object set."""
        return ObjClass.factory(self.policy, self.policy.handle.p.p.class_val_to_struct[(<sepol.avtab_ptr_t>self.handle).key.target_class - 1])

    @property
    def perms(self):
        """The rule's permission set."""
        raise RuleUseError("{0} rules do not have a permission set.".format(self.ruletype))

    @property
    def default(self):
        """The rule's default type."""
        cdef const qpol_type_t *t
        if qpol_terule_get_default_type(self.policy.handle, self.handle, &t):
            ex = LowLevelPolicyError("Error reading default type for TE rule: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return Type.factory(self.policy, <sepol.type_datum_t *>t)

    @property
    def filename(self):
        """The type_transition rule's file name."""
        if self.ruletype == TERuletype.type_transition:
            raise TERuleNoFilename
        else:
            raise RuleUseError("{0} rules do not have file names".format(self.ruletype))

    @property
    def conditional(self):
        """The rule's conditional expression."""
        cdef const qpol_cond_t *c
        if qpol_terule_get_cond(self.policy.handle, self.handle, &c):
            ex = LowLevelPolicyError("Error reading TE rule conditional: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        if c:
            return Conditional.factory(self.policy, <sepol.cond_node_t *>c)
        else:
            raise RuleNotConditional

    @property
    def conditional_block(self):
        """
        The conditional block of the rule (T/F)

        For example, if the policy looks like this:

        if ( the_conditional_expression ) {
            If the rule is here, this property is True
        } else {
            If the rule is here, this property is False
        }
        """
        cdef const qpol_cond_t *c
        cdef uint32_t which

        if qpol_terule_get_cond(self.policy.handle, self.handle, &c):
            ex = LowLevelPolicyError("Error reading TE rule conditional: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        if not c:
            raise RuleNotConditional

        if qpol_terule_get_which_list(self.policy.handle, self.handle, &which):
            ex = LowLevelPolicyError("Error reading TE rule conditional block: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return bool(which)

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        for s, t in itertools.product(self.source.expand(), self.target.expand()):
            yield expanded_terule_factory(self, s, t)


cdef class FileNameTERule(PolicyRule):

    """A type_transition type enforcement rule with filename."""

    cdef:
        sepol.filename_trans_t *handle
        readonly object ruletype
        Type dft

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.filename_trans_t *symbol, sepol.type_datum_t *dft):
        """Factory function for creating TERule objects."""
        r = FileNameTERule(Type.factory(policy, dft))
        r.policy = policy
        r.handle = symbol
        return r

    def __init__(self, dft):
        self.ruletype = TERuletype.type_transition
        self.dft = dft

    def __str__(self):
        rule_string = "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default} {0.filename};". \
            format(self)

        try:
            rule_string += " [ {0.conditional} ]:{0.conditional_block}".format(self)
        except RuleNotConditional:
            pass

        return rule_string

    def __hash__(self):
        try:
            cond = self.conditional
            cond_block = self.conditional_block
        except RuleNotConditional:
            cond = None
            cond_block = None

        try:
            filename = self.filename
        except (TERuleNoFilename, RuleUseError):
            filename = None

        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{1}|{2}|{3}".format(
            self, filename, cond, cond_block))

    def __lt__(self, other):
        return str(self) < str(other)

    def __deepcopy__(self, memo):
        # shallow copy as all of the members are immutable
        newobj = FileNameTERule.factory(self.policy, self.handle, self.dft.handle)
        memo[id(self)] = newobj
        return newobj

    def __getstate__(self):
        return (self.policy, self._pickle())

    def __setstate__(self, state):
        self.policy = state[0]
        self._unpickle(state[1])

    cdef bytes _pickle(self):
        return <bytes>(<char *>self.handle)

    cdef _unpickle(self, bytes handle):
        memcpy(&self.handle, <char *>handle, sizeof(sepol.filename_trans_t*))

    def _eq(self, FileNameTERule other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def source(self):
        """The rule's source type/attribute."""
        return type_or_attr_factory(self.policy, self.policy.handle.p.p.type_val_to_struct[self.handle.stype - 1])

    @property
    def target(self):
        """The rule's target type/attribute."""
        return type_or_attr_factory(self.policy, self.policy.handle.p.p.type_val_to_struct[self.handle.ttype - 1])

    @property
    def tclass(self):
        """The rule's object class."""
        return ObjClass.factory(self.policy, self.policy.handle.p.p.class_val_to_struct[self.handle.ttype - 1])

    @property
    def perms(self):
        """The rule's permission set."""
        raise RuleUseError("{0} rules do not have a permission set.".format(self.ruletype))

    @property
    def default(self):
        """The rule's default type."""
        return self.dft

    @property
    def filename(self):
        """The type_transition rule's file name."""
        return intern(self.handle.name)

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        for s, t in itertools.product(self.source.expand(), self.target.expand()):
            yield expanded_filename_terule_factory(self, s, t)


cdef class ExpandedAVRule(AVRule):

    """An expanded access vector type enforcement rule."""

    cdef:
        public object source
        public object target
        public object perms
        public object origin

    def __hash__(self):
        try:
            cond = self.conditional
            cond_block = self.conditional_block
        except RuleNotConditional:
            cond = None
            cond_block = None

        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{1}|{2}".format(
            self, cond, cond_block))

    def __lt__(self, other):
        return str(self) < str(other)


cdef class ExpandedAVRuleXperm(AVRuleXperm):

    """An expanded extended permission access vector type enforcement rule."""

    cdef:
        public object source
        public object target
        public object perms
        public object origin

    def __hash__(self):
        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{0.xperm_type}".format(self))

    def __lt__(self, other):
        return str(self) < str(other)


cdef class ExpandedTERule(TERule):

    """An expanded type_* type enforcement rule."""

    cdef:
        public object source
        public object target
        public object origin

    def __hash__(self):
        try:
            cond = self.conditional
            cond_block = self.conditional_block
        except RuleNotConditional:
            cond = None
            cond_block = None

        try:
            filename = self.filename
        except (TERuleNoFilename, RuleUseError):
            filename = None

        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{1}|{2}|{3}".format(
            self, filename, cond, cond_block))

    def __lt__(self, other):
        return str(self) < str(other)


cdef class ExpandedFileNameTERule(FileNameTERule):

    """An expanded filename type_transition rule."""

    cdef:
        public object source
        public object target
        public object origin

    def __hash__(self):
        try:
            cond = self.conditional
            cond_block = self.conditional_block
        except RuleNotConditional:
            cond = None
            cond_block = None

        try:
            filename = self.filename
        except (TERuleNoFilename, RuleUseError):
            filename = None

        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{1}|{2}|{3}".format(
            self, filename, cond, cond_block))

    def __lt__(self, other):
        return str(self) < str(other)


#
# Iterators
#
cdef class FileNameTERuleIterator(HashtabIterator):

    """Iterate over FileNameTERules in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating FileNameTERule iterators."""
        i = FileNameTERuleIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return FileNameTERule.factory(self.policy, <sepol.filename_trans_t *>self.curr.key,
                                      <sepol.type_datum_t *>self.curr.datum)
