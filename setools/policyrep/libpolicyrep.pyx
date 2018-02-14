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
#cython: language_level=3, c_string_type=str, c_string_encoding=ascii

from cpython.mem cimport PyMem_Malloc, PyMem_Free
from libc.errno cimport errno, EPERM, ENOENT, ENOMEM, EINVAL
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t, uintptr_t
from libc.stdlib cimport free
from libc.string cimport memcpy, strerror
from posix.stat cimport S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFREG, S_IFLNK, S_IFSOCK

cimport sepol

from .exception import InvalidPolicy, MLSDisabled, InvalidBoolean, InvalidCategory, InvalidClass, \
    InvalidCommon, InvalidInitialSid, InvalidLevel, InvalidLevelDecl, InvalidRange, InvalidRole, \
    InvalidSensitivity, InvalidType, InvalidUser, InvalidRuleType, InvalidBoundsType, \
    InvalidConstraintType, InvalidDefaultType, InvalidFSUseType, InvalidMLSRuleType, \
    InvalidRBACRuleType, InvalidTERuleType, SymbolUseError, RuleUseError, ConstraintUseError, \
    NoStatement, InvalidDefaultValue, InvalidDefaultRange, NoCommon, NoDefaults, \
    RuleNotConditional, TERuleNoFilename, LowLevelPolicyError

cdef extern from "<stdarg.h>":
    ctypedef struct va_list:
        pass

cdef extern from "<sys/socket.h>":
    ctypedef unsigned int socklen_t
    cdef int AF_INET
    cdef int AF_INET6

cdef extern from "<netinet/in.h>":
    cdef int INET6_ADDRSTRLEN
    cdef int IPPROTO_DCCP
    cdef int IPPROTO_TCP
    cdef int IPPROTO_UDP

cdef extern from "<arpa/inet.h>":
    cdef const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)

cdef extern from "include/qpol/avrule_query.h":
    ctypedef struct qpol_avrule_t:
        pass
    cdef int QPOL_RULE_ALLOW
    cdef int QPOL_RULE_NEVERALLOW
    cdef int QPOL_RULE_AUDITALLOW
    cdef int QPOL_RULE_DONTAUDIT
    int qpol_policy_get_avrule_iter(const qpol_policy_t * policy, uint32_t rule_type_mask, qpol_iterator_t ** iter)
    int qpol_avrule_get_source_type(const qpol_policy_t * policy, const qpol_avrule_t * rule, const qpol_type_t ** source)
    int qpol_avrule_get_target_type(const qpol_policy_t * policy, const qpol_avrule_t * rule, const qpol_type_t ** target)
    int qpol_avrule_get_object_class(const qpol_policy_t * policy, const qpol_avrule_t * rule, const qpol_class_t ** obj_class)
    int qpol_avrule_get_perm_iter(const qpol_policy_t * policy, const qpol_avrule_t * rule, qpol_iterator_t ** perms)
    cdef int QPOL_RULE_XPERMS_ALLOW
    cdef int QPOL_RULE_XPERMS_AUDITALLOW
    cdef int QPOL_RULE_XPERMS_DONTAUDIT
    cdef int QPOL_RULE_XPERMS_NEVERALLOW
    int qpol_avrule_get_xperm_iter(const qpol_policy_t * policy, const qpol_avrule_t * rule, qpol_iterator_t ** xperms)
    int qpol_avrule_get_is_extended(const qpol_policy_t * policy, const qpol_avrule_t * rule, uint32_t * is_extended)
    int qpol_avrule_get_xperm_type(const qpol_policy_t * policy, const qpol_avrule_t * rule, char ** type)
    int qpol_avrule_get_rule_type(const qpol_policy_t * policy, const qpol_avrule_t * rule, uint32_t * rule_type)
    int qpol_avrule_get_cond(const qpol_policy_t * policy, const qpol_avrule_t * rule, const qpol_cond_t ** cond)
    int qpol_avrule_get_is_enabled(const qpol_policy_t * policy, const qpol_avrule_t * rule, uint32_t * is_enabled)
    int qpol_avrule_get_which_list(const qpol_policy_t * policy, const qpol_avrule_t * rule, uint32_t * which_list)

cdef extern from "include/qpol/bool_query.h":
    ctypedef struct qpol_bool_t:
        pass

cdef extern from "include/qpol/bounds_query.h":
    ctypedef struct qpol_typebounds_t:
        pass
    int qpol_policy_get_typebounds_iter(const qpol_policy_t *policy, qpol_iterator_t **iter)
    int qpol_typebounds_get_parent_name(const qpol_policy_t *policy, const qpol_typebounds_t *datum, const char **name)
    int qpol_typebounds_get_child_name(const qpol_policy_t *policy, const qpol_typebounds_t *datum, const char **name)

cdef extern from "include/qpol/class_perm_query.h":
    ctypedef struct qpol_class_t:
        pass
    ctypedef struct qpol_common_t:
        pass
    # permissions
    int qpol_perm_get_class_iter(const qpol_policy_t * policy, const char *perm, qpol_iterator_t ** classes)
    int qpol_perm_get_common_iter(const qpol_policy_t * policy, const char *perm, qpol_iterator_t ** commons)
    int qpol_policy_get_class_by_name(const qpol_policy_t * policy, const char *name, const qpol_class_t ** obj_class)
    int qpol_policy_get_class_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_class_get_value(const qpol_policy_t * policy, const qpol_class_t * obj_class, uint32_t * value)
    # classes
    int qpol_class_get_common(const qpol_policy_t * policy, const qpol_class_t * obj_class, const qpol_common_t ** common)
    int qpol_class_get_perm_iter(const qpol_policy_t * policy, const qpol_class_t * obj_class, qpol_iterator_t ** perms)
    int qpol_class_get_name(const qpol_policy_t * policy, const qpol_class_t * obj_class, const char **name)
    # commons
    int qpol_policy_get_common_by_name(const qpol_policy_t * policy, const char *name, const qpol_common_t ** common)
    int qpol_policy_get_common_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_common_get_value(const qpol_policy_t * policy, const qpol_common_t * common, uint32_t * value)
    int qpol_common_get_perm_iter(const qpol_policy_t * policy, const qpol_common_t * common, qpol_iterator_t ** perms)
    int qpol_common_get_name(const qpol_policy_t * policy, const qpol_common_t * common, const char **name)

cdef extern from "include/qpol/cond_query.h":
    ctypedef struct qpol_cond_t:
        pass
    ctypedef struct qpol_cond_expr_node_t:
        pass
    cdef int QPOL_COND_RULE_LIST
    cdef int QPOL_COND_RULE_ENABLED
    int qpol_policy_get_cond_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_cond_get_expr_node_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, qpol_iterator_t ** iter)
    int qpol_cond_get_av_true_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t rule_type_mask, qpol_iterator_t ** iter)
    int qpol_cond_get_te_true_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t rule_type_mask, qpol_iterator_t ** iter)
    int qpol_cond_get_av_false_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t rule_type_mask, qpol_iterator_t ** iter)
    int qpol_cond_get_te_false_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t rule_type_mask, qpol_iterator_t ** iter)
    int qpol_cond_eval(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t * is_true)
    cdef int QPOL_COND_EXPR_BOOL
    cdef int QPOL_COND_EXPR_NOT
    cdef int QPOL_COND_EXPR_OR
    cdef int QPOL_COND_EXPR_AND
    cdef int QPOL_COND_EXPR_XOR
    cdef int QPOL_COND_EXPR_EQ
    cdef int QPOL_COND_EXPR_NEQ
    int qpol_cond_expr_node_get_expr_type(const qpol_policy_t * policy, const qpol_cond_expr_node_t * node, uint32_t * expr_type)
    int qpol_cond_expr_node_get_bool(const qpol_policy_t * policy, const qpol_cond_expr_node_t * node, qpol_bool_t ** cond_bool)

cdef extern from "include/qpol/constraint_query.h":
    ctypedef struct qpol_constraint_t:
        pass
    ctypedef struct qpol_validatetrans_t:
        pass
    ctypedef struct qpol_constraint_expr_node_t:
        pass
    int qpol_policy_get_constraint_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_constraint_get_class(const qpol_policy_t * policy, const qpol_constraint_t * constr, const qpol_class_t ** obj_class)
    int qpol_constraint_get_perm_iter(const qpol_policy_t * policy, const qpol_constraint_t * constr, qpol_iterator_t ** iter)
    int qpol_constraint_get_expr_iter(const qpol_policy_t * policy, const qpol_constraint_t * constr, qpol_iterator_t ** iter)
    int qpol_policy_get_validatetrans_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_validatetrans_get_class(const qpol_policy_t * policy, const qpol_validatetrans_t * vtrans, const qpol_class_t ** obj_class)
    int qpol_validatetrans_get_expr_iter(const qpol_policy_t * policy, const qpol_validatetrans_t * vtrans, qpol_iterator_t ** iter)
    cdef int QPOL_CEXPR_TYPE_NOT
    cdef int QPOL_CEXPR_TYPE_AND
    cdef int QPOL_CEXPR_TYPE_OR
    cdef int QPOL_CEXPR_TYPE_ATTR
    cdef int QPOL_CEXPR_TYPE_NAMES
    int qpol_constraint_expr_node_get_expr_type(const qpol_policy_t * policy, const qpol_constraint_expr_node_t * expr, uint32_t * expr_type)
    cdef int QPOL_CEXPR_SYM_USER
    cdef int QPOL_CEXPR_SYM_ROLE
    cdef int QPOL_CEXPR_SYM_TYPE
    cdef int QPOL_CEXPR_SYM_TARGET
    cdef int QPOL_CEXPR_SYM_XTARGET
    cdef int QPOL_CEXPR_SYM_L1L2
    cdef int QPOL_CEXPR_SYM_L1H2
    cdef int QPOL_CEXPR_SYM_H1L2
    cdef int QPOL_CEXPR_SYM_H1H2
    cdef int QPOL_CEXPR_SYM_L1H1
    cdef int QPOL_CEXPR_SYM_L2H2
    int qpol_constraint_expr_node_get_sym_type(const qpol_policy_t * policy, const qpol_constraint_expr_node_t * expr, uint32_t * sym_type)
    cdef int QPOL_CEXPR_OP_EQ
    cdef int QPOL_CEXPR_OP_NEQ
    cdef int QPOL_CEXPR_OP_DOM
    cdef int QPOL_CEXPR_OP_DOMBY
    cdef int QPOL_CEXPR_OP_INCOMP
    int qpol_constraint_expr_node_get_op(const qpol_policy_t * policy, const qpol_constraint_expr_node_t * expr, uint32_t * op)
    int qpol_constraint_expr_node_get_names_iter(const qpol_policy_t * policy, const qpol_constraint_expr_node_t * expr, qpol_iterator_t ** iter)
    int qpol_class_get_constraint_iter(const qpol_policy_t * policy, const qpol_class_t * obj_class, qpol_iterator_t ** constr)
    int qpol_class_get_validatetrans_iter(const qpol_policy_t * policy, const qpol_class_t * obj_class,  qpol_iterator_t ** vtrans)

cdef extern from "include/qpol/ftrule_query.h":
    ctypedef struct qpol_filename_trans_t:
        pass
    int qpol_policy_get_filename_trans_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_filename_trans_get_source_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_type_t ** source)
    int qpol_filename_trans_get_target_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_type_t ** target)
    int qpol_filename_trans_get_default_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_type_t ** dflt)
    int qpol_filename_trans_get_object_class(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_class_t ** obj_class)
    int qpol_filename_trans_get_filename(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const char ** name)

cdef extern from "include/qpol/iterator.h":
    ctypedef struct qpol_iterator_t:
        pass
    void qpol_iterator_destroy(qpol_iterator_t ** iter)
    int qpol_iterator_get_item(const qpol_iterator_t * iter, void **item)
    int qpol_iterator_next(qpol_iterator_t * iter)
    int qpol_iterator_end(const qpol_iterator_t * iter)
    int qpol_iterator_get_size(const qpol_iterator_t * iter, size_t * size)

cdef extern from "qpol_internal.h":
    ctypedef struct qpol_policy_t:
        sepol.sepol_policydb *p

cdef extern from "include/qpol/policy.h":
    ctypedef void (*qpol_callback_fn_t)(void *varg, const qpol_policy_t * policy, int level, const char *msg)
    cdef enum qpol_capability_e:
        QPOL_CAP_ATTRIB_NAMES,
        QPOL_CAP_SYN_RULES,
        QPOL_CAP_LINE_NUMBERS,
        QPOL_CAP_CONDITIONALS,
        QPOL_CAP_MLS,
        QPOL_CAP_POLCAPS,
        QPOL_CAP_MODULES,
        QPOL_CAP_RULES_LOADED,
        QPOL_CAP_SOURCE,
        QPOL_CAP_NEVERALLOW,
        QPOL_CAP_BOUNDS,
        QPOL_CAP_DEFAULT_OBJECTS,
        QPOL_CAP_DEFAULT_TYPE,
        QPOL_CAP_PERMISSIVE,
        QPOL_CAP_FILENAME_TRANS,
        QPOL_CAP_ROLETRANS,
        QPOL_CAP_XPERM_IOCTL

    cdef int QPOL_POLICY_UNKNOWN
    cdef int QPOL_POLICY_KERNEL_SOURCE
    cdef int QPOL_POLICY_KERNEL_BINARY
    cdef int QPOL_POLICY_MODULE_BINARY
    int qpol_policy_open_from_file(const char *filename, qpol_policy_t ** policy, qpol_callback_fn_t fn, void *varg, const int options)
    void qpol_policy_destroy(qpol_policy_t ** policy)
    int qpol_policy_get_policy_version(const qpol_policy_t * policy, unsigned int *version)
    int qpol_policy_get_type(const qpol_policy_t * policy, int *type)
    int qpol_policy_has_capability(const qpol_policy_t * policy, qpol_capability_e cap)
    int qpol_policy_get_policy_handle_unknown(const qpol_policy_t * policy, unsigned int *handle_unknown)
    int qpol_policy_get_target_platform(const qpol_policy_t *policy, int *target_platform)

cdef extern from "include/qpol/rbacrule_query.h":
    ctypedef struct qpol_role_allow_t:
        pass
    ctypedef struct qpol_role_trans_t:
        pass
    int qpol_policy_get_role_allow_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_role_allow_get_source_role(const qpol_policy_t * policy, const qpol_role_allow_t * rule, const qpol_role_t ** source)
    int qpol_role_allow_get_target_role(const qpol_policy_t * policy, const qpol_role_allow_t * rule, const qpol_role_t ** target)
    int qpol_policy_get_role_trans_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_role_trans_get_source_role(const qpol_policy_t * policy, const qpol_role_trans_t * rule, const qpol_role_t ** source)
    int qpol_role_trans_get_target_type(const qpol_policy_t * policy, const qpol_role_trans_t * rule, const qpol_type_t ** target)
    int qpol_role_trans_get_object_class(const qpol_policy_t * policy, const qpol_role_trans_t * rule, const qpol_class_t ** obj_class)
    int qpol_role_trans_get_default_role(const qpol_policy_t * policy, const qpol_role_trans_t * rule, const qpol_role_t ** dflt)

cdef extern from "include/qpol/role_query.h":
    ctypedef struct qpol_role_t:
        pass

cdef extern from "include/qpol/terule_query.h":
    ctypedef struct qpol_terule_t:
        pass
    cdef uint32_t QPOL_RULE_TYPE_TRANS
    cdef uint32_t QPOL_RULE_TYPE_CHANGE
    cdef uint32_t QPOL_RULE_TYPE_MEMBER
    int qpol_policy_get_terule_iter(const qpol_policy_t * policy, uint32_t rule_type_mask, qpol_iterator_t ** iter)
    int qpol_terule_get_source_type(const qpol_policy_t * policy, const qpol_terule_t * rule, const qpol_type_t ** source)
    int qpol_terule_get_target_type(const qpol_policy_t * policy, const qpol_terule_t * rule, const qpol_type_t ** target)
    int qpol_terule_get_object_class(const qpol_policy_t * policy, const qpol_terule_t * rule, const qpol_class_t ** obj_class)
    int qpol_terule_get_default_type(const qpol_policy_t * policy, const qpol_terule_t * rule, const qpol_type_t ** dflt)
    int qpol_terule_get_rule_type(const qpol_policy_t * policy, const qpol_terule_t * rule, uint32_t * rule_type)
    int qpol_terule_get_cond(const qpol_policy_t * policy, const qpol_terule_t * rule, const qpol_cond_t ** cond)
    int qpol_terule_get_is_enabled(const qpol_policy_t * policy, const qpol_terule_t * rule, uint32_t * is_enabled)
    int qpol_terule_get_which_list(const qpol_policy_t * policy, const qpol_terule_t * rule, uint32_t * which_list)

cdef extern from "include/qpol/type_query.h":
    ctypedef struct qpol_type_t:
        pass

cdef extern from "include/qpol/user_query.h":
    ctypedef struct qpol_user_t:
        pass


# this must be here so that the PolicyEnum subclasses are created correctly.
# otherwise you get an error during runtime
include "util.pxi"

include "boolcond.pxi"
include "bounds.pxi"
include "constraint.pxi"
include "context.pxi"
include "default.pxi"
include "fscontext.pxi"
include "initsid.pxi"
include "mls.pxi"
include "mlsrule.pxi"
include "netcontext.pxi"
include "objclass.pxi"
include "polcap.pxi"
include "rbacrule.pxi"
include "role.pxi"
include "rule.pxi"
include "selinuxpolicy.pxi"
include "symbol.pxi"
include "terule.pxi"
include "typeattr.pxi"
include "user.pxi"
include "xencontext.pxi"


cdef QpolIterator qpol_iterator_factory(SELinuxPolicy policy, qpol_iterator_t *iter, factory,
                                        suppress=None):
    i = QpolIterator()
    i.policy = policy
    i.iter = iter
    i.factory = factory
    i.suppress = suppress
    return i


cdef class QpolIterator:
    cdef:
        qpol_iterator_t *iter
        SELinuxPolicy policy
        object factory
        object suppress

    def __dealloc__(self):
        if self.iter:
            qpol_iterator_destroy(&self.iter)

    def __iter__(self):
        return self

    def __next__(self):
        cdef void *item

        while not qpol_iterator_end(self.iter):
            qpol_iterator_get_item(self.iter, &item)
            qpol_iterator_next(self.iter)
            w = QpolIteratorItem()
            w.obj = item

            if self.suppress:
                # this is to handle where factory functions
                # throw exceptions since aliases are included
                # in some qpol iterators (i.e. that's how
                # the policy structure works)
                try:
                    return self.factory(self.policy, w)
                except self.suppress:
                    pass

            else:
                return self.factory(self.policy, w)

        raise StopIteration

    def __len__(self):
        cdef size_t s

        qpol_iterator_get_size(self.iter, &s)
        return s


cdef class QpolIteratorItem:

    """Wrap void pointers so they can be passed easily."""

    cdef void *obj


cdef str string_factory_iter(SELinuxPolicy _, QpolIteratorItem item):

    """Factory function for returning strings from qpol iterators."""

    return intern(<const char *> item.obj)


cdef sepol.hashtab_datum_t hashtab_search(sepol.hashtab_t h, sepol.const_hashtab_key_t key):
    """
    Search a hash table by key.

    This is derived from the libsepol function of the same name.
    """

    cdef:
        int hvalue
        sepol.hashtab_ptr_t cur

    hvalue = h.hash_value(h, key)
    cur = h.htable[hvalue]
    while cur != NULL and h.keycmp(h, key, cur.key) > 0:
        cur = cur.next

    if cur == NULL or h.keycmp(h, key, cur.key) != 0:
        return NULL

    return cur.datum


cdef int ebitmap_get_bit(sepol.ebitmap_t *e, unsigned int bit):
    """
    Get a specific bit value.

    This is derived from the libsepol function of the same name.
    """

    cdef sepol.ebitmap_node_t *n

    if e.highbit < bit:
        return 0

    n = e.node
    while n and n.startbit <= bit:
        if (n.startbit + sepol.MAPSIZE) > bit:
            if n.map & (sepol.MAPBIT << (bit - n.startbit)):
                return 1
            else:
                return 0

        n = n.next

    return 0
