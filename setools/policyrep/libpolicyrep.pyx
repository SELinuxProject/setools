# Copyright 2017, Chris PeBenito <pebenito@ieee.org>
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
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t
from libc.stdlib cimport free
from libc.string cimport memcpy, strerror
from posix.stat cimport S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFREG, S_IFLNK, S_IFSOCK

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

cdef extern from "sepol/policydb.h":
    cdef int SEPOL_DENY_UNKNOWN
    cdef int SEPOL_REJECT_UNKNOWN
    cdef int SEPOL_ALLOW_UNKNOWN
    cdef int SEPOL_TARGET_SELINUX
    cdef int SEPOL_TARGET_XEN

cdef extern from "sepol/policydb/policydb.h":
    cdef int POLICYDB_VERSION_MAX
    cdef int POLICYDB_VERSION_MIN

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
    int qpol_policy_get_bool_by_name(const qpol_policy_t * policy, const char *name, qpol_bool_t ** datum)
    int qpol_policy_get_bool_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_bool_get_value(const qpol_policy_t * policy, const qpol_bool_t * datum, uint32_t * value)
    int qpol_bool_get_state(const qpol_policy_t * policy, const qpol_bool_t * datum, int *state)
    int qpol_bool_set_state(qpol_policy_t * policy, qpol_bool_t * datum, int state)
    int qpol_bool_set_state_no_eval(qpol_policy_t * policy, qpol_bool_t * datum, int state)
    int qpol_bool_get_name(const qpol_policy_t * policy, const qpol_bool_t * datum, const char **name)

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

cdef extern from "include/qpol/context_query.h":
    ctypedef struct qpol_context_t:
        pass
    int qpol_context_get_user(const qpol_policy_t * policy, const qpol_context_t * context, const qpol_user_t ** user)
    int qpol_context_get_role(const qpol_policy_t * policy, const qpol_context_t * context, const qpol_role_t ** role)
    int qpol_context_get_type(const qpol_policy_t * policy, const qpol_context_t * context, const qpol_type_t ** type)
    int qpol_context_get_range(const qpol_policy_t * policy, const qpol_context_t * context, const qpol_mls_range_t ** range)

cdef extern from "include/qpol/default_object_query.h":
    ctypedef struct qpol_default_object_t:
        pass
    int qpol_policy_get_default_object_iter(const qpol_policy_t *policy, qpol_iterator_t **iter)
    int qpol_default_object_get_class(const qpol_policy_t *policy, const qpol_default_object_t *datum, const qpol_class_t **cls)
    int qpol_default_object_get_user_default(const qpol_policy_t *policy, const qpol_default_object_t *datum, const char **value)
    int qpol_default_object_get_role_default(const qpol_policy_t *policy, const qpol_default_object_t *datum, const char **value)
    int qpol_default_object_get_type_default(const qpol_policy_t *policy, const qpol_default_object_t *datum, const char **value)
    int qpol_default_object_get_range_default(const qpol_policy_t *policy, const qpol_default_object_t *datum, const char **value)

cdef extern from "include/qpol/fs_use_query.h":
    ctypedef struct qpol_fs_use_t:
        pass
    int qpol_policy_get_fs_use_by_name(const qpol_policy_t * policy, const char *name, const qpol_fs_use_t ** ocon)
    int qpol_policy_get_fs_use_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_fs_use_get_name(const qpol_policy_t * policy, const qpol_fs_use_t * ocon, const char **name)
    cdef int QPOL_FS_USE_XATTR
    cdef int QPOL_FS_USE_TRANS
    cdef int QPOL_FS_USE_TASK
    cdef int QPOL_FS_USE_GENFS
    cdef int QPOL_FS_USE_NONE
    cdef int QPOL_FS_USE_PSID
    int qpol_fs_use_get_behavior(const qpol_policy_t * policy, const qpol_fs_use_t * ocon, uint32_t * behavior)
    int qpol_fs_use_get_context(const qpol_policy_t * policy, const qpol_fs_use_t * ocon, const qpol_context_t ** context)

cdef extern from "include/qpol/ftrule_query.h":
    ctypedef struct qpol_filename_trans_t:
        pass
    int qpol_policy_get_filename_trans_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_filename_trans_get_source_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_type_t ** source)
    int qpol_filename_trans_get_target_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_type_t ** target)
    int qpol_filename_trans_get_default_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_type_t ** dflt)
    int qpol_filename_trans_get_object_class(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_class_t ** obj_class)
    int qpol_filename_trans_get_filename(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const char ** name)

cdef extern from "include/qpol/genfscon_query.h":
    ctypedef struct qpol_genfscon_t:
        pass
    extern int qpol_policy_get_genfscon_by_name(const qpol_policy_t * policy, const char *name, const char *path, qpol_genfscon_t ** genfscon)
    extern int qpol_policy_get_genfscon_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    extern int qpol_genfscon_get_name(const qpol_policy_t * policy, const qpol_genfscon_t * genfs, const char **name)
    extern int qpol_genfscon_get_path(const qpol_policy_t * policy, const qpol_genfscon_t * genfs, const char **path)
    cdef int QPOL_CLASS_ALL
    cdef int QPOL_CLASS_BLK_FILE
    cdef int QPOL_CLASS_CHR_FILE
    cdef int QPOL_CLASS_DIR
    cdef int QPOL_CLASS_FIFO_FILE
    cdef int QPOL_CLASS_FILE
    cdef int QPOL_CLASS_LNK_FILE
    cdef int QPOL_CLASS_SOCK_FILE
    extern int qpol_genfscon_get_class(const qpol_policy_t * policy, const qpol_genfscon_t * genfs, uint32_t * obj_class)
    extern int qpol_genfscon_get_context(const qpol_policy_t * policy, const qpol_genfscon_t * genfscon, const qpol_context_t ** context)

cdef extern from "include/qpol/isid_query.h":
    ctypedef struct qpol_isid_t:
        pass
    extern int qpol_policy_get_isid_by_name(const qpol_policy_t * policy, const char *name, const qpol_isid_t ** ocon)
    extern int qpol_policy_get_isid_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    extern int qpol_isid_get_name(const qpol_policy_t * policy, const qpol_isid_t * ocon, const char **name)
    extern int qpol_isid_get_context(const qpol_policy_t * policy, const qpol_isid_t * ocon, const qpol_context_t ** context)

cdef extern from "include/qpol/iterator.h":
    ctypedef struct qpol_iterator_t:
        pass
    void qpol_iterator_destroy(qpol_iterator_t ** iter)
    int qpol_iterator_get_item(const qpol_iterator_t * iter, void **item)
    int qpol_iterator_next(qpol_iterator_t * iter)
    int qpol_iterator_end(const qpol_iterator_t * iter)
    int qpol_iterator_get_size(const qpol_iterator_t * iter, size_t * size)

cdef extern from "include/qpol/mls_query.h":
    ctypedef struct qpol_level_t:
        pass
    ctypedef struct qpol_cat_t:
        pass
    ctypedef struct qpol_mls_range_t:
        pass
    ctypedef struct qpol_mls_level_t:
        pass
    ctypedef struct qpol_semantic_level_t:
        pass
    # level
    int qpol_policy_get_level_by_name(const qpol_policy_t * policy, const char *name, const qpol_level_t ** datum)
    int qpol_policy_get_level_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_level_get_isalias(const qpol_policy_t * policy, const qpol_level_t * datum, unsigned char *isalias)
    int qpol_level_get_value(const qpol_policy_t * policy, const qpol_level_t * datum, uint32_t * value)
    int qpol_level_get_cat_iter(const qpol_policy_t * policy, const qpol_level_t * datum, qpol_iterator_t ** cats)
    int qpol_level_get_name(const qpol_policy_t * policy, const qpol_level_t * datum, const char **name)
    int qpol_level_get_alias_iter(const qpol_policy_t * policy, const qpol_level_t * datum, qpol_iterator_t ** aliases)
    # category
    int qpol_policy_get_cat_by_name(const qpol_policy_t * policy, const char *name, const qpol_cat_t ** datum)
    int qpol_policy_get_cat_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_cat_get_value(const qpol_policy_t * policy, const qpol_cat_t * datum, uint32_t * value)
    int qpol_cat_get_isalias(const qpol_policy_t * policy, const qpol_cat_t * datum, unsigned char *isalias)
    int qpol_cat_get_name(const qpol_policy_t * policy, const qpol_cat_t * datum, const char **name)
    int qpol_cat_get_alias_iter(const qpol_policy_t * policy, const qpol_cat_t * datum, qpol_iterator_t ** aliases)
    # MLS range
    int qpol_mls_range_get_low_level(const qpol_policy_t * policy, const qpol_mls_range_t * range, const qpol_mls_level_t ** level)
    int qpol_mls_range_get_high_level(const qpol_policy_t * policy, const qpol_mls_range_t * range, const qpol_mls_level_t ** level)
    # MLS level
    int qpol_mls_level_get_sens_name(const qpol_policy_t * policy, const qpol_mls_level_t * level, const char **name)
    int qpol_mls_level_get_cat_iter(const qpol_policy_t * policy, const qpol_mls_level_t * level, qpol_iterator_t ** cats)
    # Semantic levels
    int qpol_policy_get_semantic_level_by_name(const qpol_policy_t * policy, const char *name, qpol_semantic_level_t ** datum)
    int qpol_semantic_level_add_cats_by_name(const qpol_policy_t * policy, const qpol_semantic_level_t * level, const char *low, const char *high)
    int qpol_mls_level_from_semantic_level(const qpol_policy_t * policy, qpol_semantic_level_t * src, qpol_mls_level_t **dest)
    void qpol_semantic_level_destroy(qpol_semantic_level_t * level)
    # Semantic ranges
    int qpol_policy_get_mls_range_from_mls_levels(const qpol_policy_t * policy, const qpol_mls_level_t * low, const qpol_mls_level_t *high, qpol_mls_range_t **dest)

cdef extern from "include/qpol/mlsrule_query.h":
    ctypedef struct qpol_range_trans_t:
        pass
    int qpol_policy_get_range_trans_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_range_trans_get_source_type(const qpol_policy_t * policy, const qpol_range_trans_t * rule, const qpol_type_t ** source)
    int qpol_range_trans_get_target_type(const qpol_policy_t * policy, const qpol_range_trans_t * rule, const qpol_type_t ** target)
    int qpol_range_trans_get_target_class(const qpol_policy_t * policy, const qpol_range_trans_t * rule,  const qpol_class_t ** target)
    int qpol_range_trans_get_range(const qpol_policy_t * policy, const qpol_range_trans_t * rule, const qpol_mls_range_t ** range)

cdef extern from "include/qpol/netifcon_query.h":
    ctypedef struct qpol_netifcon_t:
        pass
    int qpol_policy_get_netifcon_by_name(const qpol_policy_t * policy, const char *name, const qpol_netifcon_t ** ocon)
    int qpol_policy_get_netifcon_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_netifcon_get_name(const qpol_policy_t * policy, const qpol_netifcon_t * ocon, const char **name)
    int qpol_netifcon_get_msg_con(const qpol_policy_t * policy, const qpol_netifcon_t * ocon, const qpol_context_t ** context)
    int qpol_netifcon_get_if_con(const qpol_policy_t * policy, const qpol_netifcon_t * ocon, const qpol_context_t ** context)

cdef extern from "include/qpol/nodecon_query.h":
    cdef unsigned char QPOL_IPV4
    cdef unsigned char QPOL_IPV6
    ctypedef struct qpol_nodecon_t:
        pass
    int qpol_policy_get_nodecon_by_node(const qpol_policy_t * policy, uint32_t addr[4], uint32_t mask[4],  unsigned char protocol, qpol_nodecon_t ** ocon)
    int qpol_policy_get_nodecon_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_nodecon_get_addr(const qpol_policy_t * policy, const qpol_nodecon_t * ocon, uint32_t ** addr, unsigned char *protocol)
    int qpol_nodecon_get_mask(const qpol_policy_t * policy, const qpol_nodecon_t * ocon, uint32_t ** mask, unsigned char *protocol)
    int qpol_nodecon_get_protocol(const qpol_policy_t * policy, const qpol_nodecon_t * ocon, unsigned char *protocol)
    int qpol_nodecon_get_context(const qpol_policy_t * policy, const qpol_nodecon_t * ocon, const qpol_context_t ** context)

cdef extern from "include/qpol/polcap_query.h":
    ctypedef struct qpol_polcap_t:
        pass
    int qpol_policy_get_polcap_iter(const qpol_policy_t *policy, qpol_iterator_t **iter)
    int qpol_polcap_get_name(const qpol_policy_t *policy, const qpol_polcap_t *datum, const char **name)

cdef extern from "include/qpol/policy.h":
    ctypedef struct qpol_policy_t:
        pass
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

cdef extern from "include/qpol/portcon_query.h":
    ctypedef struct qpol_portcon_t:
        pass
    int qpol_policy_get_portcon_by_port(const qpol_policy_t * policy, uint16_t low, uint16_t high, uint8_t protocol, const qpol_portcon_t ** ocon)
    int qpol_policy_get_portcon_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_portcon_get_protocol(const qpol_policy_t * policy, const qpol_portcon_t * ocon, uint8_t * protocol)
    int qpol_portcon_get_low_port(const qpol_policy_t * policy, const qpol_portcon_t * ocon, uint16_t * port)
    int qpol_portcon_get_high_port(const qpol_policy_t * policy, const qpol_portcon_t * ocon, uint16_t * port)
    int qpol_portcon_get_context(const qpol_policy_t * policy, const qpol_portcon_t * ocon, const qpol_context_t ** context)

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
    int qpol_policy_get_role_by_name(const qpol_policy_t * policy, const char *name, const qpol_role_t ** datum)
    int qpol_policy_get_role_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_role_get_value(const qpol_policy_t * policy, const qpol_role_t * datum, uint32_t * value)
    int qpol_role_get_dominate_iter(const qpol_policy_t * policy, const qpol_role_t * datum, qpol_iterator_t ** dominates)
    int qpol_role_get_type_iter(const qpol_policy_t * policy, const qpol_role_t * datum, qpol_iterator_t ** types)
    int qpol_role_get_name(const qpol_policy_t * policy, const qpol_role_t * datum, const char **name)

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
    int qpol_policy_get_type_by_name(const qpol_policy_t * policy, const char *name, const qpol_type_t ** datum)
    int qpol_policy_get_type_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_type_get_value(const qpol_policy_t * policy, const qpol_type_t * datum, uint32_t * value)
    int qpol_type_get_isalias(const qpol_policy_t * policy, const qpol_type_t * datum, unsigned char *isalias)
    int qpol_type_get_isattr(const qpol_policy_t * policy, const qpol_type_t * datum, unsigned char *isattr)
    int qpol_type_get_ispermissive(const qpol_policy_t * policy, const qpol_type_t * datum, unsigned char *ispermissive)
    int qpol_type_get_type_iter(const qpol_policy_t * policy, const qpol_type_t * datum, qpol_iterator_t ** types)
    int qpol_type_get_attr_iter(const qpol_policy_t * policy, const qpol_type_t * datum, qpol_iterator_t ** attrs)
    int qpol_type_get_name(const qpol_policy_t * policy, const qpol_type_t * datum, const char **name)
    int qpol_type_get_alias_iter(const qpol_policy_t * policy, const qpol_type_t * datum, qpol_iterator_t ** aliases)

cdef extern from "include/qpol/user_query.h":
    ctypedef struct qpol_user_t:
        pass
    int qpol_policy_get_user_by_name(const qpol_policy_t * policy, const char *name, const qpol_user_t ** datum)
    int qpol_policy_get_user_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
    int qpol_user_get_value(const qpol_policy_t * policy, const qpol_user_t * datum, uint32_t * value)
    int qpol_user_get_role_iter(const qpol_policy_t * policy, const qpol_user_t * datum, qpol_iterator_t ** roles)
    int qpol_user_get_range(const qpol_policy_t * policy, const qpol_user_t * datum, const qpol_mls_range_t ** range)
    int qpol_user_get_dfltlevel(const qpol_policy_t * policy, const qpol_user_t * datum, const qpol_mls_level_t ** level)
    int qpol_user_get_name(const qpol_policy_t * policy, const qpol_user_t * datum, const char **name)

cdef extern from "include/qpol/xen_query.h":
    ctypedef struct qpol_iomemcon_t:
        pass
    ctypedef struct qpol_ioportcon_t:
        pass
    ctypedef struct qpol_pcidevicecon_t:
        pass
    ctypedef struct qpol_pirqcon_t:
        pass
    ctypedef struct qpol_devicetreecon_t:
        pass
    int qpol_policy_get_iomemcon_by_addr(const qpol_policy_t *policy, uint64_t low, uint64_t high, const qpol_iomemcon_t **ocon)
    int qpol_policy_get_iomemcon_iter(const qpol_policy_t *policy, qpol_iterator_t **iter)
    int qpol_iomemcon_get_low_addr(const qpol_policy_t *policy, const qpol_iomemcon_t *ocon, uint64_t *addr)
    int qpol_iomemcon_get_high_addr(const qpol_policy_t *policy, const qpol_iomemcon_t *ocon, uint64_t *addr)
    int qpol_iomemcon_get_context(const qpol_policy_t *policy, const qpol_iomemcon_t *ocon, const qpol_context_t **context)
    int qpol_policy_get_ioportcon_by_port(const qpol_policy_t *policy, uint32_t low, uint32_t high, const qpol_ioportcon_t **ocon)
    int qpol_policy_get_ioportcon_iter(const qpol_policy_t *policy, qpol_iterator_t **iter)
    int qpol_ioportcon_get_low_port(const qpol_policy_t *policy, const qpol_ioportcon_t *ocon, uint32_t *port)
    int qpol_ioportcon_get_high_port(const qpol_policy_t *policy, const qpol_ioportcon_t *ocon, uint32_t *port)
    int qpol_ioportcon_get_context(const qpol_policy_t *policy, const qpol_ioportcon_t *ocon, const qpol_context_t **context)
    int qpol_policy_get_pcidevicecon_iter(const qpol_policy_t *policy, qpol_iterator_t **iter)
    int qpol_pcidevicecon_get_device(const qpol_policy_t *policy, const qpol_pcidevicecon_t *ocon, uint32_t *device)
    int qpol_pcidevicecon_get_context(const qpol_policy_t *policy, const qpol_pcidevicecon_t *ocon, const qpol_context_t **context)
    int qpol_policy_get_pirqcon_iter(const qpol_policy_t *policy, qpol_iterator_t **iter)
    int qpol_pirqcon_get_irq(const qpol_policy_t *policy, const qpol_pirqcon_t *ocon, uint16_t *irq)
    int qpol_pirqcon_get_context(const qpol_policy_t *policy, const qpol_pirqcon_t *ocon, const qpol_context_t **context)
    int qpol_policy_get_devicetreecon_iter(const qpol_policy_t *policy, qpol_iterator_t **iter)
    int qpol_devicetreecon_get_path(const qpol_policy_t *policy, const qpol_devicetreecon_t *ocon, char **path)
    int qpol_devicetreecon_get_context(const qpol_policy_t *policy, const qpol_devicetreecon_t *ocon, const qpol_context_t **context)


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

    def size(self):
        cdef size_t s

        qpol_iterator_get_size(self.iter, &s)
        return s


cdef class QpolIteratorItem:

    """Wrap void pointers so they can be passed easily."""

    cdef void *obj


cdef str string_factory_iter(SELinuxPolicy _, QpolIteratorItem item):

    """Factory function for returning strings from qpol iterators."""

    return <const char *> item.obj
