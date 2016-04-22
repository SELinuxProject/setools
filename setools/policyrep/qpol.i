/**
 * SWIG declarations for libqpol.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006-2008 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

%module qpol

%{
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>
#include "include/qpol/avrule_query.h"
#include "include/qpol/bool_query.h"
#include "include/qpol/class_perm_query.h"
#include "include/qpol/cond_query.h"
#include "include/qpol/constraint_query.h"
#include "include/qpol/context_query.h"
#include "include/qpol/fs_use_query.h"
#include "include/qpol/genfscon_query.h"
#include "include/qpol/isid_query.h"
#include "include/qpol/iterator.h"
#include "include/qpol/mls_query.h"
#include "include/qpol/mlsrule_query.h"
#include "include/qpol/module.h"
#include "include/qpol/netifcon_query.h"
#include "include/qpol/nodecon_query.h"
#include "include/qpol/policy.h"
#include "include/qpol/policy_extend.h"
#include "include/qpol/portcon_query.h"
#include "include/qpol/rbacrule_query.h"
#include "include/qpol/role_query.h"
#include "include/qpol/syn_rule_query.h"
#include "include/qpol/terule_query.h"
#include "include/qpol/type_query.h"
#include "include/qpol/user_query.h"
#include "include/qpol/util.h"
#include "include/qpol/xen_query.h"

/* Provide hooks so that language-specific modules can define the
 * callback function, used by the handler in
 * qpol_policy_open_from_file().
 */
SWIGEXPORT qpol_callback_fn_t qpol_swig_message_callback = NULL;
SWIGEXPORT void * qpol_swig_message_callback_arg = NULL;

%}

%include exception.i
%include stdint.i

/* handle size_t as architecture dependent */
#ifdef SWIGWORDSIZE64
typedef uint64_t size_t;
#else
typedef uint32_t size_t;
#endif

%inline %{
    /* cast void * to char * as it can't have a constructor */
    const char * to_str(void *x) {
        return (const char *)x;
    }

    /* cast a void * to int, while freeing the pointer */
    int to_int_with_free(void *x) {
        int i = *(int *)x;
        free(x);
        return i;
    }
%}
%{
/* C Bridge to Python logging callback */
__attribute__ ((format(printf, 4, 0)))
static void qpol_log_callback(void *varg,
                              const qpol_policy_t * p __attribute__ ((unused)),
                              int level,
                              const char *fmt,
                              va_list va_args)
{
    /* Expand to a full string to avoid any C format string
     * or variable args handling when passing to Python
     */

    PyObject *py_callback, *rc;
    char *str = NULL;

    if(vasprintf(&str, fmt, va_args) < 0)
        return;

    py_callback = (PyObject *) varg;

    /* this char* casting doesn't make sense, but this runs afoul of -Werror
     * otherwise as the Python library doesn't do const char* */
    rc = PyObject_CallFunction(py_callback, (char*)"(is)", level, str);
    Py_XDECREF(rc);
    free(str);
}
%}

%pythoncode %{
import logging
from functools import wraps

def QpolGenerator(cast):
    """
    A decorator which converts qpol iterators into Python generators.

    Qpol iterators use void* to be generic about their contents.
    The purpose of the _from_void functions below is to wrap
    the pointer casting, hence the "cast" variable name here.

    Decorator parameter:
    cast    A wrapper function which casts the qpol iterator return pointer
            to the proper C data type pointer.  The Python function
            reference to the C Python extension is used, for example:

            @QpolGenerator(_qpol.qpol_type_from_void)
    """

    def decorate(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            qpol_iter = func(*args)
            while not qpol_iter.isend():
                yield cast(qpol_iter.item())
                qpol_iter.next_()

        return wrapper
    return decorate

def qpol_logger(level, msg):
    """Log qpol messages via Python logging."""
    logging.getLogger(__name__).debug(msg)

def qpol_policy_factory(path):
    """Factory function for qpol policy objects."""
    # The main purpose here is to hook in the
    # above logger callback.
    return qpol_policy_t(path, 0, qpol_logger)
%}

/* qpol_policy */
#define QPOL_POLICY_OPTION_NO_NEVERALLOWS 0x00000001
#define QPOL_POLICY_OPTION_NO_RULES       0x00000002
/* add maximum and minimum policy versions supported by the statically linked libsepol */
%constant int QPOL_POLICY_MAX_VERSION = POLICYDB_VERSION_MAX;
%constant int QPOL_POLICY_MIN_VERSION = POLICYDB_VERSION_MIN;
typedef struct qpol_policy {} qpol_policy_t;
typedef void (*qpol_callback_fn_t) (void *varg, struct qpol_policy * policy, int level, const char *fmt, va_list va_args);

typedef enum qpol_capability
{
    QPOL_CAP_ATTRIB_NAMES,
    QPOL_CAP_SYN_RULES,
    QPOL_CAP_LINE_NUMBERS,
    QPOL_CAP_CONDITIONALS,
    QPOL_CAP_MLS,
    QPOL_CAP_MODULES,
    QPOL_CAP_RULES_LOADED,
    QPOL_CAP_SOURCE,
    QPOL_CAP_NEVERALLOW,
    QPOL_CAP_POLCAPS,
    QPOL_CAP_BOUNDS,
    QPOL_CAP_DEFAULT_OBJECTS,
    QPOL_CAP_DEFAULT_TYPE,
    QPOL_CAP_PERMISSIVE,
    QPOL_CAP_FILENAME_TRANS,
    QPOL_CAP_ROLETRANS,
    QPOL_CAP_XPERM_IOCTL
} qpol_capability_e;
%exception qpol_policy {
  $action
  if (!result) {
    if (errno == EINVAL) {
        PyErr_SetString(PyExc_SyntaxError, "Invalid policy.");
    } else {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, arg1);
    }
    return NULL;
  }
}
%extend qpol_policy {
    qpol_policy(const char *path, const int options, PyObject *py_callback) {
        qpol_policy_t *p;

        if (!PyCallable_Check(py_callback)) {
            PyErr_SetString(PyExc_TypeError, "Callback parameter must be callable");
            return NULL;
        }

        qpol_policy_open_from_file(path, &p, qpol_log_callback, (void*)py_callback, options);
        return p;
    }
    ~qpol_policy() {
        qpol_policy_destroy(&self);
    };

    int version () {
        unsigned int v;
        (void)qpol_policy_get_policy_version(self, &v); /* only error is on null parameters neither can be here */
        return (int) v;
    };

    const char *handle_unknown () {
        unsigned int h;
        qpol_policy_get_policy_handle_unknown(self, &h);

        switch (h) {
            case SEPOL_DENY_UNKNOWN: return "deny";
            case SEPOL_REJECT_UNKNOWN: return "reject";
            case SEPOL_ALLOW_UNKNOWN: return "allow";
            default: return "unknown";
        }
    };

    /* This is whether SELinux or XEN policy */
    const char *target_platform () {
        int t;
        (void)qpol_policy_get_target_platform(self, &t);
        switch (t) {
            case SEPOL_TARGET_SELINUX: return "selinux";
            case SEPOL_TARGET_XEN: return "xen";
            default: return "unknown";
        }
    };

    int capability (qpol_capability_e cap) {
        return qpol_policy_has_capability(self, cap);
    };

    %newobject type_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_type_from_void) %}
    qpol_iterator_t *type_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_type_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t type_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_type_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject role_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_role_from_void) %}
    qpol_iterator_t *role_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_role_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t role_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_role_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject level_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_level_from_void) %}
    qpol_iterator_t *level_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_level_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t level_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_level_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject cat_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_cat_from_void) %}
    qpol_iterator_t *cat_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_cat_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t cat_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_cat_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject user_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_user_from_void) %}
    qpol_iterator_t *user_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_user_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t user_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_user_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };


    %newobject bool_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_bool_from_void) %}
    qpol_iterator_t *bool_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_bool_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t bool_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_bool_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject class_iter(char*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_class_from_void) %}
    qpol_iterator_t *class_iter(char *perm=NULL) {
        qpol_iterator_t *iter;
        if (perm) {
            if (qpol_perm_get_class_iter(self, perm, &iter)) {
                SWIG_exception(SWIG_RuntimeError, "Could not get class iterator");
            }
        } else {
            if (qpol_policy_get_class_iter(self, &iter)) {
                SWIG_exception(SWIG_MemoryError, "Out of Memory");
            }
        }
        return iter;
    fail:
        return NULL;
    };

    size_t class_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_class_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject common_iter(char*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_common_from_void) %}
    qpol_iterator_t *common_iter(char *perm=NULL) {
        qpol_iterator_t *iter;
        if (perm) {
            if (qpol_perm_get_common_iter(self, perm, &iter)) {
                SWIG_exception(SWIG_RuntimeError, "Could not get common iterator");
            }
        } else {
            if (qpol_policy_get_common_iter(self, &iter)) {
                SWIG_exception(SWIG_MemoryError, "Out of Memory");
            }
        }
        return iter;
    fail:
        return NULL;
    };

    size_t common_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_common_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject fs_use_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_fs_use_from_void) %}
    qpol_iterator_t *fs_use_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_fs_use_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t fs_use_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_fs_use_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject genfscon_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_genfscon_from_void) %}
    qpol_iterator_t *genfscon_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_genfscon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t genfscon_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_genfscon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject isid_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_isid_from_void) %}
    qpol_iterator_t *isid_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_isid_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t isid_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_isid_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject netifcon_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_netifcon_from_void) %}
    qpol_iterator_t *netifcon_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_netifcon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
            return NULL;
    };

    size_t netifcon_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_netifcon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject nodecon_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_nodecon_from_void) %}
    qpol_iterator_t *nodecon_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_nodecon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t nodecon_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_nodecon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject portcon_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_portcon_from_void) %}
    qpol_iterator_t *portcon_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_portcon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t portcon_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_portcon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject constraint_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_constraint_from_void) %}
    qpol_iterator_t *constraint_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_constraint_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
    fail:
        return NULL;
    };

    size_t constraint_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_constraint_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject validatetrans_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_validatetrans_from_void) %}
    qpol_iterator_t *validatetrans_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_validatetrans_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
    fail:
        return NULL;
    };

    size_t validatetrans_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_validatetrans_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject role_allow_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_role_allow_from_void) %}
    qpol_iterator_t *role_allow_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_role_allow_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t role_allow_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_role_allow_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject role_trans_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_role_trans_from_void) %}
    qpol_iterator_t *role_trans_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_role_trans_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t role_trans_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_role_trans_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject range_trans_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_range_trans_from_void) %}
    qpol_iterator_t *range_trans_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_range_trans_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t range_trans_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_range_trans_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject avrule_iter(int);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_avrule_from_void) %}
    qpol_iterator_t *avrule_iter() {
        qpol_iterator_t *iter;
        uint32_t rule_types = QPOL_RULE_ALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT;

        if (qpol_policy_has_capability(self, QPOL_CAP_NEVERALLOW))
            rule_types |= QPOL_RULE_NEVERALLOW;

        if (qpol_policy_get_avrule_iter(self, rule_types, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t avrule_allow_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_avrule_iter(self, QPOL_RULE_ALLOW, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    size_t avrule_auditallow_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_avrule_iter(self, QPOL_RULE_AUDITALLOW, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    size_t avrule_neverallow_count() {
        if (qpol_policy_has_capability(self, QPOL_CAP_NEVERALLOW)) {
            qpol_iterator_t *iter;
            size_t count = 0;
            if (qpol_policy_get_avrule_iter(self, QPOL_RULE_NEVERALLOW, &iter)) {
                SWIG_exception(SWIG_MemoryError, "Out of Memory");
            }
            qpol_iterator_get_size(iter, &count);
            return count;
        } else {
            return 0;
        }
    fail:
        return 0;
    };

    size_t avrule_dontaudit_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_avrule_iter(self, QPOL_RULE_DONTAUDIT, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject avulex_iter(int);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_avrule_from_void) %}
    qpol_iterator_t *avrulex_iter() {
        qpol_iterator_t *iter;
        uint32_t rule_types = QPOL_RULE_XPERMS_ALLOW | QPOL_RULE_XPERMS_AUDITALLOW | QPOL_RULE_XPERMS_DONTAUDIT;

        if (qpol_policy_has_capability(self, QPOL_CAP_NEVERALLOW))
            rule_types |= QPOL_RULE_XPERMS_NEVERALLOW;

        if (qpol_policy_get_avrule_iter(self, rule_types, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t avrule_allowx_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_avrule_iter(self, QPOL_RULE_XPERMS_ALLOW, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    size_t avrule_auditallowx_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_avrule_iter(self, QPOL_RULE_XPERMS_AUDITALLOW, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    size_t avrule_neverallowx_count() {
        if (qpol_policy_has_capability(self, QPOL_CAP_NEVERALLOW)) {
            qpol_iterator_t *iter;
            size_t count = 0;
            if (qpol_policy_get_avrule_iter(self, QPOL_RULE_XPERMS_NEVERALLOW, &iter)) {
                SWIG_exception(SWIG_MemoryError, "Out of Memory");
            }
            qpol_iterator_get_size(iter, &count);
            return count;
        } else {
            return 0;
        }
    fail:
        return 0;
    };

    size_t avrule_dontauditx_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_avrule_iter(self, QPOL_RULE_XPERMS_DONTAUDIT, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject terule_iter(int);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_terule_from_void) %}
    qpol_iterator_t *terule_iter() {
        qpol_iterator_t *iter;
        uint32_t rule_types = QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER;

        if (qpol_policy_get_terule_iter(self, rule_types, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t terule_trans_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_terule_iter(self, QPOL_RULE_TYPE_TRANS, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    size_t terule_change_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_terule_iter(self, QPOL_RULE_TYPE_CHANGE, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    size_t terule_member_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_terule_iter(self, QPOL_RULE_TYPE_MEMBER, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject cond_iter();
    qpol_iterator_t *cond_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_cond_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t cond_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_cond_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject filename_trans_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_filename_trans_from_void) %}
    qpol_iterator_t *filename_trans_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_filename_trans_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
    fail:
        return NULL;
    };

    size_t filename_trans_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_filename_trans_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject permissive_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_type_from_void) %}
    qpol_iterator_t *permissive_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_permissive_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
    fail:
        return NULL;
    };

    size_t permissive_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_permissive_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject typebounds_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_typebounds_from_void) %}
    qpol_iterator_t *typebounds_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_typebounds_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
    fail:
        return NULL;
    };

    %newobject polcap_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_polcap_from_void) %}
    qpol_iterator_t *polcap_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_polcap_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
    fail:
        return NULL;
    };

    size_t polcap_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_polcap_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject default_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_default_object_from_void) %}
    qpol_iterator_t *default_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_default_object_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
    fail:
        return NULL;
    };

    %newobject iomemcon_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_iomemcon_from_void) %}
    qpol_iterator_t *iomemcon_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_iomemcon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
    fail:
        return NULL;
    };
    size_t iomemcon_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_iomemcon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject ioportcon_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_ioportcon_from_void) %}
    qpol_iterator_t *ioportcon_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_ioportcon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
    fail:
        return NULL;
    };

    size_t ioportcon_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_ioportcon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject pcidevicecon_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_pcidevicecon_from_void) %}
    qpol_iterator_t *pcidevicecon_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_pcidevicecon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
    fail:
        return NULL;
    };
    size_t pcidevicecon_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_pcidevicecon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject pirqcon_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_pirqcon_from_void) %}
    qpol_iterator_t *pirqcon_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_pirqcon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
    fail:
        return NULL;
    };
    size_t pirqcon_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_pirqcon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };

    %newobject devicetreecon_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_devicetreecon_from_void) %}
    qpol_iterator_t *devicetreecon_iter() {
        qpol_iterator_t *iter;
        if (qpol_policy_get_devicetreecon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
    fail:
        return NULL;
    };
    size_t devicetreecon_count() {
        qpol_iterator_t *iter;
        size_t count = 0;
        if (qpol_policy_get_devicetreecon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        qpol_iterator_get_size(iter, &count);
        return count;
    fail:
        return 0;
    };
};

/* qpol iterator */
typedef struct qpol_iterator {} qpol_iterator_t;
%extend qpol_iterator {
    /* user never directly creates, but SWIG expects a constructor */
    qpol_iterator() {
        SWIG_exception(SWIG_TypeError, "User may not create iterators difectly");
    fail:
        return NULL;
    };
    ~qpol_iterator() {
        qpol_iterator_destroy(&self);
    };
    void *item() {
        void *i;
        if (qpol_iterator_get_item(self, &i)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get item");
        }
        return i;
    fail:
        return NULL;
    };
    void next_() {
        if (qpol_iterator_next(self)) {
            SWIG_exception(SWIG_RuntimeError, "Error advancing iterator");
        }
    fail:
        return;
    };
    int isend() {
        return qpol_iterator_end(self);
    };
    size_t size() {
        size_t s;
        if (qpol_iterator_get_size(self, &s)) {
            SWIG_exception(SWIG_ValueError, "Could not get iterator size");
        }
        return s;
    fail:
        return 0;
    };
};

/* qpol type */
typedef struct qpol_type {} qpol_type_t;
%extend qpol_type {
    %exception qpol_type {
      $action
      if (!result) {
        PyErr_SetString(PyExc_ValueError, "Invalid type or attribute.");
        return NULL;
      }
    }
    qpol_type(qpol_policy_t *p, const char *name) {
        const qpol_type_t *t;
        qpol_policy_get_type_by_name(p, name, &t);
        return (qpol_type_t*)t;
    };
    ~qpol_type() {
        /* no op */
        return;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_type_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get type name");
        }
        return name;
    fail:
        return NULL;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        if (qpol_type_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get type value");
        }
    fail:
        return (int) v;
    };
    int isalias(qpol_policy_t *p) {
        unsigned char i;
        if (qpol_type_get_isalias(p, self, &i)) {
            SWIG_exception(SWIG_ValueError, "Could not determine whether type is an alias");
        }
    fail:
        return (int)i;
    };
    int isattr(qpol_policy_t *p) {
        unsigned char i;
        if (qpol_type_get_isattr(p, self, &i)) {
            SWIG_exception(SWIG_ValueError, "Could not determine whether type is an attribute");
        }
    fail:
        return (int)i;
    };
    int ispermissive(qpol_policy_t *p) {
        unsigned char i;
        if (qpol_type_get_ispermissive(p, self, &i)) {
            SWIG_exception(SWIG_ValueError, "Could not determine whether type is permissive");
        }
    fail:
        return (int)i;
    };

    %newobject type_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_type_from_void) %}
    qpol_iterator_t *type_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        int retv = qpol_type_get_type_iter(p, self, &iter);
        if (retv < 0) {
            SWIG_exception(SWIG_RuntimeError, "Could not get attribute types");
        } else if (retv > 0) {
            SWIG_exception(SWIG_TypeError, "Type is not an attribute");
        }
    fail:
        return iter;
    };

    %newobject attr_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_type_from_void) %}
    qpol_iterator_t *attr_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        int retv = qpol_type_get_attr_iter(p, self, &iter);
        if (retv < 0) {
            SWIG_exception(SWIG_RuntimeError, "Could not get type attributes");
        } else if (retv > 0) {
            SWIG_exception(SWIG_TypeError, "Type is an attribute");
        }
    fail:
        return iter;
    };

    %newobject alias_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *alias_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_type_get_alias_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get type aliases");
        }
    fail:
        return iter;
    };

    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_permissive_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get permissive type name");
        }
        return name;
    fail:
        return NULL;
    };
 };
%inline %{
    qpol_type_t *qpol_type_from_void(void *x) {
        return (qpol_type_t*)x;
    };
%}

/* qpol role */
typedef struct qpol_role {} qpol_role_t;
%extend qpol_role {
    %exception qpol_role {
      $action
      if (!result) {
        PyErr_SetString(PyExc_ValueError, "Invalid type or attribute.");
        return NULL;
      }
    }
    qpol_role(qpol_policy_t *p, const char *name) {
        const qpol_role_t *r;
        qpol_policy_get_role_by_name(p, name, &r);
        return (qpol_role_t*)r;
    };
    ~qpol_role() {
        /* no op */
        return;
    };
    int value (qpol_policy_t *p) {
        uint32_t v;
        if (qpol_role_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get role value");
        }
    fail:
        return (int) v;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_role_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get role name");
        }
        return name;
    fail:
        return NULL;
    };

    %newobject type_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_type_from_void) %}
    qpol_iterator_t *type_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_role_get_type_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get role types");
        }
    fail:
        return iter;
    };

    %newobject dominate_iter(qpol_policy_t*);
    qpol_iterator_t *dominate_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_role_get_dominate_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get dominated roles");
        }
    fail:
        return iter;
    };
};
%inline %{
    qpol_role_t *qpol_role_from_void(void *x) {
        return (qpol_role_t*)x;
    };
%}

/* qpol level */
typedef struct qpol_level {} qpol_level_t;
%extend qpol_level {
    %exception qpol_level {
      $action
      if (!result) {
        if (errno == EINVAL) {
            PyErr_SetString(PyExc_ValueError, "Invalid level.");
        } else {
            PyErr_SetFromErrno(PyExc_OSError);
        }

        return NULL;
      }
    }
    qpol_level(qpol_policy_t *p, const char *name) {
        const qpol_level_t *l;
        qpol_policy_get_level_by_name(p, name, &l);
        return (qpol_level_t*)l;
    };

    ~qpol_level() {
        /* no op */
        return;
    };
    int isalias(qpol_policy_t *p) {
        unsigned char i;
        if (qpol_level_get_isalias(p, self, &i)) {
            SWIG_exception(SWIG_ValueError, "Could not determine whether level is an alias");
        }
    fail:
            return (int)i;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        if (qpol_level_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get level sensitivity value");
        }
    fail:
        return (int) v;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_level_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get level sensitivity name");
        }
        return name;
    fail:
        return NULL;
    };

    %newobject cat_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_cat_from_void) %}
    qpol_iterator_t *cat_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_level_get_cat_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get level categories");
        }
    fail:
        return iter;
    };

    %newobject alias_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *alias_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_level_get_alias_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get level aliases");
        }
    fail:
        return iter;
    };
};
%inline %{
    qpol_level_t *qpol_level_from_void(void *x) {
        return (qpol_level_t*)x;
    };
%}

/* qpol cat */
typedef struct qpol_cat {} qpol_cat_t;
%extend qpol_cat {
    %exception qpol_cat {
      $action
      if (!result) {
        if (errno == EINVAL) {
            PyErr_SetString(PyExc_ValueError, "Invalid category.");
        } else {
            PyErr_SetFromErrno(PyExc_OSError);
        }

        return NULL;
      }
    }
    qpol_cat(qpol_policy_t *p, const char *name) {
        const qpol_cat_t *c;
        qpol_policy_get_cat_by_name(p, name, &c);
        return (qpol_cat_t*)c;
    };

    ~qpol_cat() {
        /* no op */
        return;
    };
    int isalias(qpol_policy_t *p) {
        unsigned char i;
        if (qpol_cat_get_isalias(p, self, &i)) {
            SWIG_exception(SWIG_ValueError, "Could not determine whether category is an alias");
        }
    fail:
            return (int)i;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        if (qpol_cat_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get category value");
        }
    fail:
        return (int) v;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_cat_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get category name");
        }
        return name;
    fail:
        return NULL;
    };
    %newobject alias_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *alias_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_cat_get_alias_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get category aliases");
        }
    fail:
        return iter;
    };
};
%inline %{
    qpol_cat_t *qpol_cat_from_void(void *x) {
        return (qpol_cat_t*)x;
    };
%}

/* qpol mls range */
typedef struct qpol_mls_range {} qpol_mls_range_t;
%extend qpol_mls_range {
    /*
     * TODO: determine how to conditionally destroy this range.
     * It should only be destroyed if it was looked up (user-entered)
     * Otherwise qpol will destroy the others when the policy closes.
     */
    %exception qpol_mls_range {
      $action
      if (!result) {
        if (errno == EINVAL) {
            PyErr_SetString(PyExc_ValueError, "Invalid range.");
        } else {
            PyErr_SetFromErrno(PyExc_OSError);
        }

        return NULL;
      }
    }

    qpol_mls_range(qpol_policy_t *p, qpol_mls_level_t *l, qpol_mls_level_t *h) {
        qpol_mls_range_t *range;
        qpol_policy_get_mls_range_from_mls_levels(p, l, h, &range);
        return range;
    }

    ~qpol_mls_range() {
        /* no op */
        return;
    };
    const qpol_mls_level_t *high_level(qpol_policy_t *p) {
        const qpol_mls_level_t *l;
        if (qpol_mls_range_get_high_level(p, self, &l)) {
            SWIG_exception(SWIG_ValueError, "Could not get range high levl");
        }
    fail:
        return l;
    };
    const qpol_mls_level_t *low_level(qpol_policy_t *p) {
        const qpol_mls_level_t *l;
        if (qpol_mls_range_get_low_level(p, self, &l)) {
            SWIG_exception(SWIG_ValueError, "Could not get range low levl");
        }
    fail:
        return l;
    };
};
%inline %{
    qpol_mls_range_t *qpol_mls_range_from_void(void *x) {
        return (qpol_mls_range_t*)x;
    };
%}

/* qpol semantic mls level */
typedef struct qpol_semantic_level {} qpol_semantic_level_t;
%extend qpol_semantic_level {
    %exception qpol_semantic_level {
      $action
      if (!result) {
        PyErr_SetString(PyExc_ValueError, "Invalid sensitivity name.");
        return NULL;
      }
    }

    qpol_semantic_level(qpol_policy_t *p, const char *name) {
        const qpol_semantic_level_t *l;
        qpol_policy_get_semantic_level_by_name(p, name, &l);
        return (qpol_semantic_level_t*)l;
    };

    ~qpol_semantic_level() {
        qpol_semantic_level_destroy(self);
        return;
    };

    %exception add_cats {
      $action
      if (result) {
        PyErr_SetString(PyExc_ValueError, "Invalid category name or category range.");
        return NULL;
      }
    }
    int add_cats(qpol_policy_t *p, const char *low, const char *high) {
        return qpol_semantic_level_add_cats_by_name(p, self, low, high);
    }
};

/* qpol mls level */
typedef struct qpol_mls_level {} qpol_mls_level_t;
%extend qpol_mls_level {
    %exception qpol_mls_level {
      $action
      if (!result) {
        PyErr_SetString(PyExc_ValueError, "Invalid level.");
        return NULL;
      }
    }

    qpol_mls_level(qpol_policy_t *p, qpol_semantic_level_t *l) {
        qpol_mls_level_t *level;
        qpol_mls_level_from_semantic_level(p, l, &level);
        return level;
    }

    ~qpol_mls_level() {
        /* no op */
        return;
    };
    const char *sens_name(qpol_policy_t *p) {
        const char *name;
        if (qpol_mls_level_get_sens_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get level sensitivity name");
        }
    fail:
        return name;
    };

    %newobject cat_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_cat_from_void) %}
    qpol_iterator_t *cat_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_mls_level_get_cat_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get level categories");
        }
    fail:
        return iter;
    };
};
%inline %{
    qpol_mls_level_t *qpol_mls_level_from_void(void *x) {
        return (qpol_mls_level_t*)x;
    };
%}

/* qpol user */
typedef struct qpol_user {} qpol_user_t;
%extend qpol_user {
    %exception qpol_user {
      $action
      if (!result) {
        PyErr_SetString(PyExc_ValueError, "Invalid user.");
        return NULL;
      }
    }
    qpol_user(qpol_policy_t *p, const char *name) {
        const qpol_user_t *u;
        qpol_policy_get_user_by_name(p, name, &u);
        return (qpol_user_t*)u;
    };
    ~qpol_user() {
        /* no op */
        return;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        if (qpol_user_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get user value");
        }
    fail:
        return (int) v;
    };

    %newobject role_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_role_from_void) %}
    qpol_iterator_t *role_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_user_get_role_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
    fail:
        return iter;
    };

    const qpol_mls_range_t *range(qpol_policy_t *p) {
        const qpol_mls_range_t *r;
        if (qpol_user_get_range(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get user range");
        }
    fail:
        return r;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_user_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get user name");
        }
    fail:
        return name;
    };
    const qpol_mls_level_t *dfltlevel(qpol_policy_t *p) {
        const qpol_mls_level_t *l;
        if (qpol_user_get_dfltlevel(p, self, &l)) {
            SWIG_exception(SWIG_ValueError, "Could not get user default level");
        }
    fail:
        return l;
    };
};
%inline %{
    qpol_user_t *qpol_user_from_void(void *x) {
        return (qpol_user_t*)x;
    };
%}

/* qpol bool */
typedef struct qpol_bool {} qpol_bool_t;
%extend qpol_bool {
    qpol_bool(qpol_policy_t *p, const char *name) {
        qpol_bool_t *b;
        if (qpol_policy_get_bool_by_name(p, name, &b)) {
            SWIG_exception(SWIG_RuntimeError, "Boolean does not exist");
        }
    fail:
        return b;
    };
    ~qpol_bool() {
        /* no op */
        return;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        if (qpol_bool_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get boolean value");
        }
    fail:
        return (int) v;
    };
    int state(qpol_policy_t *p) {
        int s;
        if (qpol_bool_get_state(p, self, &s)) {
            SWIG_exception(SWIG_ValueError, "Could not get boolean state");
        }
    fail:
        return s;
    };

    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_bool_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get boolean name");
        }
    fail:
        return name;
    };
};
%inline %{
    qpol_bool_t *qpol_bool_from_void(void *x) {
        return (qpol_bool_t*)x;
    };
%}

/* qpol context */
typedef struct qpol_context {} qpol_context_t;
%extend qpol_context {
    qpol_context() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_context_t objects");
    fail:
        return NULL;
    };
    ~qpol_context() {
        /* no op */
        return;
    };
     const qpol_user_t *user(qpol_policy_t *p) {
        const qpol_user_t *u;
        if (qpol_context_get_user(p, self, &u)) {
            SWIG_exception(SWIG_ValueError, "Could not get user from context");
        }
    fail:
        return u;
     };
     const qpol_role_t *role(qpol_policy_t *p) {
        const qpol_role_t *r;
        if (qpol_context_get_role(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get role from context");
        }
    fail:
        return r;
     };
     const qpol_type_t *type_(qpol_policy_t *p) {
        const qpol_type_t *t;
        if (qpol_context_get_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get type from context");
        }
    fail:
        return t;
     };
     const qpol_mls_range_t *range(qpol_policy_t *p) {
        const qpol_mls_range_t *r;
        if (qpol_context_get_range(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get range from context");
        }
    fail:
        return r;
     };
};
%inline %{
    qpol_context_t *qpol_context_from_void(void *x) {
        return (qpol_context_t*)x;
    };
%}

/* qpol class */
typedef struct qpol_class {} qpol_class_t;
%extend qpol_class {
    %exception qpol_class {
      $action
      if (!result) {
        if (errno == EINVAL) {
            PyErr_SetString(PyExc_ValueError, "Invalid class.");
        } else {
            PyErr_SetFromErrno(PyExc_OSError);
        }

        return NULL;
      }
    }
    qpol_class(qpol_policy_t *p, const char *name) {
        const qpol_class_t *c;
        qpol_policy_get_class_by_name(p, name, &c);
        return (qpol_class_t*)c;
    };

    ~qpol_class() {
        /* no op */
        return;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        if (qpol_class_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get value for class");
        }
    fail:
        return (int) v;
    };

    %exception common {
        $action
        if (!result) {
            PyErr_SetString(PyExc_ValueError, "Class does not inherit a common.");
            return NULL;
        }
    }
    const qpol_common_t *common(qpol_policy_t *p) {
        const qpol_common_t *c;
        if(qpol_class_get_common(p, self, &c)) {
            SWIG_exception(SWIG_ValueError, "Could not get common for class");
        }
    fail:
        return c;
    };
    %newobject perm_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *perm_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if(qpol_class_get_perm_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get class permissions");
        }
    fail:
        return iter;
    };

    %newobject constraint_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_constraint_from_void) %}
    qpol_iterator_t *constraint_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if(qpol_class_get_constraint_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get class constraints");
        }
    fail:
        return iter;
    };

    %newobject validatetrans_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_validatetrans_from_void) %}
    qpol_iterator_t *validatetrans_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if(qpol_class_get_validatetrans_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get class validatetrans statements");
        }
    fail:
            return iter;
    };

    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_class_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get class name");
        }
    fail:
        return name;
    };
};
%inline %{
    qpol_class_t *qpol_class_from_void(void *x) {
        return (qpol_class_t*)x;
    };
%}

/* qpol common */
typedef struct qpol_common {} qpol_common_t;
%extend qpol_common {
    %exception qpol_common {
      $action
      if (!result) {
        if (errno == EINVAL) {
            PyErr_SetString(PyExc_ValueError, "Invalid common.");
        } else {
            PyErr_SetFromErrno(PyExc_OSError);
        }

        return NULL;
      }
    }
    qpol_common(qpol_policy_t *p, const char *name) {
        const qpol_common_t *c;
        qpol_policy_get_common_by_name(p, name, &c);
        return (qpol_common_t*)c;
    };

    ~qpol_common() {
        /* no op */
        return;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        if (qpol_common_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get value for common");
        }
    fail:
        return (int) v;
    };

    %newobject perm_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *perm_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if(qpol_common_get_perm_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get common permissions");
        }
    fail:
        return iter;
    };

    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_common_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get common name");
        }
    fail:
        return name;
    };
};
%inline %{
    qpol_common_t *qpol_common_from_void(void *x) {
        return (qpol_common_t*)x;
    };
%}

/* qpol fs_use */
/* The defines QPOL_FS_USE_XATTR through QPOL_FS_USE_NONE are
 * copied from sepol/policydb/services.h.
 * QPOL_FS_USE_PSID is an extension to support v12 policies. */
#define QPOL_FS_USE_XATTR 1U
#define QPOL_FS_USE_TRANS 2U
#define QPOL_FS_USE_TASK  3U
#define QPOL_FS_USE_GENFS 4U
#define QPOL_FS_USE_NONE  5U
#define QPOL_FS_USE_PSID  6U
typedef struct qpol_fs_use {} qpol_fs_use_t;
%extend qpol_fs_use {
    qpol_fs_use(qpol_policy_t *p, const char *name) {
        const qpol_fs_use_t *f;
        if (qpol_policy_get_fs_use_by_name(p, name, &f)) {
            SWIG_exception(SWIG_RuntimeError, "FS Use Statement does not exist");
        }
    fail:
        return (qpol_fs_use_t*)f;
    };
    ~qpol_fs_use() {
        /* no op */
        return;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_fs_use_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get file system name");
        }
    fail:
        return name;
    };
    int behavior(qpol_policy_t *p) {
        uint32_t behav;
        if (qpol_fs_use_get_behavior(p, self, &behav)) {
            SWIG_exception(SWIG_ValueError, "Could not get file system labeling behavior");
        }
    fail:
        return (int) behav;
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        uint32_t behav;
        const qpol_context_t *ctx = NULL;
        qpol_fs_use_get_behavior(p, self, &behav);
        if (behav == QPOL_FS_USE_PSID) {
            SWIG_exception(SWIG_TypeError, "Cannot get context for fs_use_psid statements");
        } else if (qpol_fs_use_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get file system context");
        }
    fail:
        return ctx;
    };
};
%inline %{
    qpol_fs_use_t *qpol_fs_use_from_void(void *x) {
        return (qpol_fs_use_t*)x;
    };
%}

/* qpol genfscon */
/* values from flask do not change */
#define QPOL_CLASS_ALL        0U
#define QPOL_CLASS_BLK_FILE  11U
#define QPOL_CLASS_CHR_FILE  10U
#define QPOL_CLASS_DIR        7U
#define QPOL_CLASS_FIFO_FILE 13U
#define QPOL_CLASS_FILE       6U
#define QPOL_CLASS_LNK_FILE   9U
#define QPOL_CLASS_SOCK_FILE 12U
typedef struct qpol_genfscon {} qpol_genfscon_t;
%extend qpol_genfscon {
    qpol_genfscon(qpol_policy_t *p, const char *name, const char *path) {
        qpol_genfscon_t *g;
        if (qpol_policy_get_genfscon_by_name(p, name, path, &g)) {
            SWIG_exception(SWIG_RuntimeError, "Genfscon statement does not exist");
        }
    fail:
        return g;
    };
    ~qpol_genfscon() {
        free(self);
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_genfscon_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get file system name");
        }
    fail:
        return name;
    };
    const char *path(qpol_policy_t *p) {
        const char *path;
        if (qpol_genfscon_get_path(p, self, &path)) {
            SWIG_exception(SWIG_ValueError, "Could not get file system path");
        }
    fail:
        return path;
    };
    unsigned int object_class(qpol_policy_t *p) {
        uint32_t cls;
        if (qpol_genfscon_get_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get genfscon statement class");
        }
        switch (cls) {
            case QPOL_CLASS_BLK_FILE: return S_IFBLK;
            case QPOL_CLASS_CHR_FILE: return S_IFCHR;
            case QPOL_CLASS_DIR: return S_IFDIR;
            case QPOL_CLASS_FIFO_FILE: return S_IFIFO;
            case QPOL_CLASS_FILE: return S_IFREG;
            case QPOL_CLASS_LNK_FILE: return S_IFLNK;
            case QPOL_CLASS_SOCK_FILE: return S_IFSOCK;
            default: return 0; /* all file types */
        }
    fail:
        return 0;
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        if (qpol_genfscon_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get context for genfscon statement");
        }
    fail:
        return ctx;
    };
};
%inline %{
    qpol_genfscon_t *qpol_genfscon_from_void(void *x) {
        return (qpol_genfscon_t*)x;
    };
%}

/* qpol isid */
typedef struct qpol_isid {} qpol_isid_t;
%extend qpol_isid {
    %exception qpol_isid {
      $action
      if (!result) {
        if (errno == EINVAL) {
            PyErr_SetString(PyExc_ValueError, "Invalid initial sid name.");
        } else {
            PyErr_SetFromErrno(PyExc_OSError);
        }

        return NULL;
      }
    }
    qpol_isid(qpol_policy_t *p, const char *name) {
        const qpol_isid_t *i;
        qpol_policy_get_isid_by_name(p, name, &i);
        return (qpol_isid_t*)i;
    };

    ~qpol_isid() {
        /* no op */
        return;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_isid_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get name for initial sid");
        }
    fail:
        return name;
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        if (qpol_isid_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get context for initial sid");
        }
    fail:
        return ctx;
    };
};
%inline %{
    qpol_isid_t *qpol_isid_from_void(void *x) {
        return (qpol_isid_t*)x;
    };
%}

/* qpol netifcon */
typedef struct qpol_netifcon {} qpol_netifcon_t;
%extend qpol_netifcon {
    qpol_netifcon(qpol_policy_t *p, const char *name) {
        const qpol_netifcon_t *n;
        if (qpol_policy_get_netifcon_by_name(p, name, &n)) {
            SWIG_exception(SWIG_RuntimeError, "Netifcon statement does not exist");
        }
    fail:
        return (qpol_netifcon_t*)n;
    };
    ~qpol_netifcon() {
        /* no op */
        return;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_netifcon_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get name for netifcon statement");
        }
    fail:
        return name;
    };
    const qpol_context_t *msg_con(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        if (qpol_netifcon_get_msg_con(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get message context for netifcon statement");
        }
    fail:
        return ctx;
    };
    const qpol_context_t *if_con(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        if (qpol_netifcon_get_if_con(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get interface context for netifcon statement");
        }
    fail:
        return ctx;
    };
};
%inline %{
    qpol_netifcon_t *qpol_netifcon_from_void(void *x) {
        return (qpol_netifcon_t*)x;
    };
%}

/* qpol nodecon */
#define QPOL_IPV4 0
#define QPOL_IPV6 1
typedef struct qpol_nodecon {} qpol_nodecon_t;
%extend qpol_nodecon {
    qpol_nodecon(qpol_policy_t *p, int addr[4], int mask[4], int protocol) {
        uint32_t a[4], m[4];
        qpol_nodecon_t *n;
        a[0] = (uint32_t) addr[0]; a[1] = (uint32_t) addr[1];
        a[2] = (uint32_t) addr[2]; a[3] = (uint32_t) addr[3];
        m[0] = (uint32_t) mask[0]; m[1] = (uint32_t) mask[1];
        m[2] = (uint32_t) mask[2]; m[3] = (uint32_t) mask[3];
        if (qpol_policy_get_nodecon_by_node(p, a, m, protocol, &n)) {
            SWIG_exception(SWIG_RuntimeError, "Nodecon statement does not exist");
        }
    fail:
        return n;
    }
    ~qpol_nodecon() {
        free(self);
    };
    char *addr(qpol_policy_t *p) {
        uint32_t *a;
        unsigned char proto;
        char *addr = NULL;

        addr = malloc(INET6_ADDRSTRLEN * sizeof(char));
        if(!addr)
            SWIG_exception(SWIG_MemoryError, "Out of memory");

        if (qpol_nodecon_get_addr(p, self, &a, &proto)) {
            SWIG_exception(SWIG_ValueError, "Could not get address of nodecon statement");
        }

        if(proto == QPOL_IPV4) {
            inet_ntop(AF_INET, a, addr, INET6_ADDRSTRLEN);
        } else {
            inet_ntop(AF_INET6, a, addr, INET6_ADDRSTRLEN);
        }

    fail:
        return addr;
    };
    char *mask(qpol_policy_t *p) {
        uint32_t *m;
        unsigned char proto;
        char *mask;
        mask = malloc(INET6_ADDRSTRLEN * sizeof(char));
        if (!mask)
            SWIG_exception(SWIG_MemoryError, "Out of memory");

        if (qpol_nodecon_get_mask(p, self, &m, &proto)) {
            SWIG_exception(SWIG_ValueError, "Could not get mask of nodecon statement");
        }

        if(proto == QPOL_IPV4) {
            inet_ntop(AF_INET, m, mask, INET6_ADDRSTRLEN);
        } else {
            inet_ntop(AF_INET6, m, mask, INET6_ADDRSTRLEN);
        }
    fail:
            return mask;
    };
    int protocol(qpol_policy_t *p) {
        unsigned char proto;
        if (qpol_nodecon_get_protocol(p, self, &proto)) {
            SWIG_exception(SWIG_ValueError, "Could not get protocol for nodecon statement");
        }
    fail:
        if(proto == QPOL_IPV4) {
            return AF_INET;
        } else {
            return AF_INET6;
        }
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        if (qpol_nodecon_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get context for nodecon statement");
        }
    fail:
        return ctx;
    };
};
%inline %{
    qpol_nodecon_t *qpol_nodecon_from_void(void *x) {
        return (qpol_nodecon_t*)x;
    };
%}

/* qpol portcon */
/* from netinet/in.h */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
typedef struct qpol_portcon {} qpol_portcon_t;
%extend qpol_portcon {
    qpol_portcon(qpol_policy_t *p, uint16_t low, uint16_t high, uint8_t protocol) {
        const qpol_portcon_t *qp;
        if (qpol_policy_get_portcon_by_port(p, low, high, protocol, &qp)) {
            SWIG_exception(SWIG_RuntimeError, "Portcon statement does not exist");
        }
    fail:
        return (qpol_portcon_t*)qp;
    };
    ~qpol_portcon() {
        /* no op */
        return;
    };
    uint16_t low_port(qpol_policy_t *p) {
        uint16_t port = 0;
        if(qpol_portcon_get_low_port(p, self, &port)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get low port for portcon statement");
        }
    fail:
        return port;
    };
    uint16_t high_port(qpol_policy_t *p) {
        uint16_t port = 0;
        if(qpol_portcon_get_high_port(p, self, &port)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get high port for portcon statement");
        }
    fail:
        return port;
    };
    uint8_t protocol(qpol_policy_t *p) {
        uint8_t proto = 0;
        if (qpol_portcon_get_protocol(p, self, &proto)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get protocol for portcon statement");
        }
    fail:
        return proto;
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        if (qpol_portcon_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get context for portcon statement");
        }
    fail:
        return ctx;
    };
}
%inline %{
    qpol_portcon_t *qpol_portcon_from_void(void *x) {
        return (qpol_portcon_t*)x;
    };
%}

/* qpol constraint */
typedef struct qpol_constraint {} qpol_constraint_t;
%extend qpol_constraint {
    qpol_constraint() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_constraint_t objects");
    fail:
        return NULL;
    };
    ~qpol_constraint() {
        free(self);
    };
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *cls;
        if (qpol_constraint_get_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for constraint");
        }
    fail:
        return cls;
    };

    %newobject perm_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *perm_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_constraint_get_perm_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
    fail:
        return iter;
    };

    %newobject expr_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_constraint_expr_node_from_void) %}
    qpol_iterator_t *expr_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_constraint_get_expr_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
    fail:
            return iter;
    };
};
%inline %{
    qpol_constraint_t *qpol_constraint_from_void(void *x) {
        return (qpol_constraint_t*)x;
    };
%}

/* qpol validatetrans */
typedef struct qpol_validatetrans {} qpol_validatetrans_t;
%extend qpol_validatetrans {
    qpol_validatetrans() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_validatetrans_t objects");
    fail:
        return NULL;
    };
    ~qpol_validatetrans() {
        free(self);
    };
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *cls;
        if (qpol_validatetrans_get_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for validatetrans");
        }
    fail:
        return cls;
    };
    %newobject expr_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_constraint_expr_node_from_void) %}
    qpol_iterator_t *expr_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_validatetrans_get_expr_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
    fail:
            return iter;
    };
};
%inline %{
    qpol_validatetrans_t *qpol_validatetrans_from_void(void *x) {
        return (qpol_validatetrans_t*)x;
    };
%}

/* qpol constraint expression node */
/* expr_type values */
#define QPOL_CEXPR_TYPE_NOT   1
#define QPOL_CEXPR_TYPE_AND   2
#define QPOL_CEXPR_TYPE_OR    3
#define QPOL_CEXPR_TYPE_ATTR  4
#define QPOL_CEXPR_TYPE_NAMES 5
/* symbol type values */
#define QPOL_CEXPR_SYM_USER       1
#define QPOL_CEXPR_SYM_ROLE       2
#define QPOL_CEXPR_SYM_TYPE       4
#define QPOL_CEXPR_SYM_TARGET     8
#define QPOL_CEXPR_SYM_XTARGET   16
#define QPOL_CEXPR_SYM_L1L2      32
#define QPOL_CEXPR_SYM_L1H2      64
#define QPOL_CEXPR_SYM_H1L2     128
#define QPOL_CEXPR_SYM_H1H2     256
#define QPOL_CEXPR_SYM_L1H1     512
#define QPOL_CEXPR_SYM_L2H2    1024
/* op values */
#define QPOL_CEXPR_OP_EQ     1
#define QPOL_CEXPR_OP_NEQ    2
#define QPOL_CEXPR_OP_DOM    3
#define QPOL_CEXPR_OP_DOMBY  4
#define QPOL_CEXPR_OP_INCOMP 5
typedef struct qpol_constraint_expr_node {} qpol_constraint_expr_node_t;
%extend qpol_constraint_expr_node {
    qpol_constraint_expr_node() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_constraint_expr_node_t objects");
    fail:
        return NULL;
    };
    ~qpol_constraint_expr_node() {
        /* no op */
        return;
    };
    int expr_type(qpol_policy_t *p) {
        uint32_t et;
        if (qpol_constraint_expr_node_get_expr_type(p, self, &et)) {
            SWIG_exception(SWIG_ValueError, "Could not get expression type for node");
        }
    fail:
        return (int) et;
    };
    int sym_type(qpol_policy_t *p) {
        uint32_t st;
        if (qpol_constraint_expr_node_get_sym_type(p, self, &st)) {
            SWIG_exception(SWIG_ValueError, "Could not get symbol type for node");
        }
    fail:
        return (int) st;
    };
    int op(qpol_policy_t *p) {
        uint32_t op;
        if (qpol_constraint_expr_node_get_op(p, self, &op)) {
            SWIG_exception(SWIG_ValueError, "Could not get operator for node");
        }
    fail:
        return (int) op;
    };
    %newobject names_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *names_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_constraint_expr_node_get_names_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
    fail:
        return iter;
    };
};
%inline %{
    qpol_constraint_expr_node_t *qpol_constraint_expr_node_from_void(void *x) {
        return (qpol_constraint_expr_node_t*)x;
    };
%}

/* qpol role allow */
typedef struct qpol_role_allow {} qpol_role_allow_t;
%extend qpol_role_allow {
    qpol_role_allow() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_role_allow_t objects");
    fail:
        return NULL;
    };
    ~qpol_role_allow() {
        /* no op */
        return;
    };
    %pythoncode %{
    def rule_type(self,policy):
        return "allow"
    %}
    const qpol_role_t *source_role(qpol_policy_t *p) {
        const qpol_role_t *r;
        if (qpol_role_allow_get_source_role(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get source for role allow rule");
        }
    fail:
        return r;
    };
    const qpol_role_t *target_role(qpol_policy_t *p) {
        const qpol_role_t *r;
        if (qpol_role_allow_get_target_role(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get target for role allow rule");
        }
    fail:
        return r;
    };
};
%inline %{
    qpol_role_allow_t *qpol_role_allow_from_void(void *x) {
        return (qpol_role_allow_t*)x;
    };
%}

/* qpol role trans */
typedef struct qpol_role_trans {} qpol_role_trans_t;
%extend qpol_role_trans {
    qpol_role_trans() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_role_trans_t objects");
    fail:
        return NULL;
    };
    ~qpol_role_trans() {
        /* no op */
        return;
    };
    %pythoncode %{
    def rule_type(self,policy):
        return "role_transition"
    %}
    const qpol_role_t *source_role(qpol_policy_t *p) {
        const qpol_role_t *r;
        if (qpol_role_trans_get_source_role(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get source for role_transition rule");
        }
    fail:
        return r;
    };
    const qpol_type_t *target_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        if (qpol_role_trans_get_target_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get target for role_transition rule");
        }
    fail:
        return t;
    };
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *c;
        if (qpol_role_trans_get_object_class(p, self, &c)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for role_transition rule");
        }
    fail:
        return c;
    };
    const qpol_role_t *default_role(qpol_policy_t *p) {
        const qpol_role_t *r;
        if (qpol_role_trans_get_default_role(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get default for role_transition rule");
        }
    fail:
        return r;
    };
};
%inline %{
    qpol_role_trans_t *qpol_role_trans_from_void(void *x) {
        return (qpol_role_trans_t*)x;
    };
%}

/* qpol range trans */
typedef struct qpol_range_trans {} qpol_range_trans_t;
%extend qpol_range_trans {
    qpol_range_trans() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_range_trans_t objects");
    fail:
        return NULL;
    };
    ~qpol_range_trans() {
        /* no op */
        return;
    };
    %pythoncode %{
    def rule_type(self,policy):
        return "range_transition"
    %}

    const qpol_type_t *source_type (qpol_policy_t *p) {
        const qpol_type_t *t;
        if (qpol_range_trans_get_source_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get source for range_transition rule");
        }
    fail:
        return t;
    };
    const qpol_type_t *target_type (qpol_policy_t *p) {
        const qpol_type_t *t;
        if (qpol_range_trans_get_target_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get target for range_transition rule");      }
    fail:
        return t;
    };
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *cls;
        if (qpol_range_trans_get_target_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for range_transition rule");       }
    fail:
        return cls;
    };
    const qpol_mls_range_t *range(qpol_policy_t *p) {
        const qpol_mls_range_t *r;
        if (qpol_range_trans_get_range(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get range for range_transition rule");
        }
    fail:
        return r;
    };
};
%inline %{
    qpol_range_trans_t *qpol_range_trans_from_void(void *x) {
        return (qpol_range_trans_t*)x;
    };
%}

/* qpol av rule */
#define QPOL_RULE_ALLOW                0x0001
#define QPOL_RULE_NEVERALLOW           0x0080
#define QPOL_RULE_AUDITALLOW           0x0002
#define QPOL_RULE_DONTAUDIT            0x0004
#define QPOL_RULE_XPERMS_ALLOW         0x0100
#define QPOL_RULE_XPERMS_AUDITALLOW    0x0200
#define QPOL_RULE_XPERMS_DONTAUDIT     0x0400
#define QPOL_RULE_XPERMS_NEVERALLOW    0x0800
typedef struct qpol_avrule {} qpol_avrule_t;
%extend qpol_avrule {
    qpol_avrule() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_avrule_t objects");
    fail:
        return NULL;
    };
    ~qpol_avrule() {
        /* no op */
        return;
    };
    const char * rule_type(qpol_policy_t *p) {
        uint32_t rt;
        if (qpol_avrule_get_rule_type(p, self, &rt)) {
            SWIG_exception(SWIG_ValueError, "Could not get rule type for av rule");
        }
        switch (rt) {
            case QPOL_RULE_ALLOW: return "allow"; break;
            case QPOL_RULE_NEVERALLOW: return "neverallow"; break;
            case QPOL_RULE_AUDITALLOW: return "auditallow"; break;
            case QPOL_RULE_DONTAUDIT: return "dontaudit"; break;
            case QPOL_RULE_XPERMS_ALLOW: return "allowxperm"; break;
            case QPOL_RULE_XPERMS_NEVERALLOW: return "neverallowxperm"; break;
            case QPOL_RULE_XPERMS_AUDITALLOW: return "auditallowxperm"; break;
            case QPOL_RULE_XPERMS_DONTAUDIT: return "dontauditxperm"; break;
        }
    fail:
        return NULL;
    };
    const qpol_type_t *source_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        if (qpol_avrule_get_source_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get source for av rule");
        }
    fail:
        return t;
    };
    const qpol_type_t *target_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        if (qpol_avrule_get_target_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get target for av rule");
        }
    fail:
        return t;
    };
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *cls;
        if (qpol_avrule_get_object_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for av rule");
        }
    fail:
        return cls;
    };

    %newobject perm_iter(qpol_policy_t *p);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *perm_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_avrule_get_perm_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
    fail:
        return iter;
    };

    /* TODO, do I need an exception (similar to cond) that is thrown if you ask this on a non extended avrule? Likewise for asking for prems an an extended rule */
    %newobject xperm_iter(qpol_policy_t *p);
    %pythoncode %{ @QpolGenerator(_qpol.to_int_with_free) %}
    qpol_iterator_t *xperm_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_avrule_get_xperm_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
    fail:
        return iter;
    };
    int is_extended(qpol_policy_t *p) {
        uint32_t e;
        if (qpol_avrule_get_is_extended(p, self, &e)) {
            SWIG_exception(SWIG_ValueError, "Could not determine if av rule is extended");
        }
    fail:
        return (int) e;
    };
    const char * xperm_type(qpol_policy_t *p) {
        char *xt;
        if (qpol_avrule_get_xperm_type(p, self, &xt)) {
            SWIG_exception(SWIG_ValueError, "Could not get xperm type for av rule");
        }
    fail:
        return xt;
    };

    %exception cond {
        $action
        if (!result) {
            PyErr_SetString(PyExc_AttributeError, "Rule is not conditional.");
            return NULL;
        }
    }
    const qpol_cond_t *cond(qpol_policy_t *p) {
        const qpol_cond_t *c;
        qpol_avrule_get_cond(p, self, &c);
        return c;
    };
    int is_enabled(qpol_policy_t *p) {
        uint32_t e;
        if (qpol_avrule_get_is_enabled(p, self, &e)) {
            SWIG_exception(SWIG_ValueError, "Could not determine if av rule is enabled");
        }
    fail:
        return (int) e;
    };

    %exception which_list {
        $action
        if (result < 0) {
            PyErr_SetString(PyExc_AttributeError, "Rule is not conditional.");
            return NULL;
        }
    }
    int which_list(qpol_policy_t *p) {
        const qpol_cond_t *c;
        uint32_t which = 0;
        qpol_avrule_get_cond(p, self, &c);
        if (c == NULL) {
            return -1;
        } else if (qpol_avrule_get_which_list(p, self, &which)) {
            return -1;
        }
        return (int) which;
    };
    %newobject syn_avrule_iter(qpol_policy_t*);
    qpol_iterator_t *syn_avrule_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_avrule_get_syn_avrule_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
    fail:
        return iter;
    };
};
%inline %{
    qpol_avrule_t *qpol_avrule_from_void(void *x) {
        return (qpol_avrule_t*)x;
    };
%}

/* qpol te rule */
#define QPOL_RULE_TYPE_TRANS   16
#define QPOL_RULE_TYPE_CHANGE  64
#define QPOL_RULE_TYPE_MEMBER  32
typedef struct qpol_terule {} qpol_terule_t;
%extend qpol_terule {
    qpol_terule() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_terule_t objects");
    fail:
        return NULL;
    };
    ~qpol_terule() {
        /* no op */
        return;
    };
    const char * rule_type(qpol_policy_t *p) {
        uint32_t rt;
        if (qpol_terule_get_rule_type(p, self, &rt)) {
            SWIG_exception(SWIG_ValueError, "Could not get rule type for te rule");
        }
        switch (rt) {
            case QPOL_RULE_TYPE_TRANS: return "type_transition"; break;
            case QPOL_RULE_TYPE_CHANGE: return "type_change"; break;
            case QPOL_RULE_TYPE_MEMBER: return "type_member"; break;
        }
    fail:
        return NULL;
    };
    const qpol_type_t *source_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        if (qpol_terule_get_source_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get source for te rule");
        }
    fail:
        return t;
    };
    const qpol_type_t *target_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        if (qpol_terule_get_target_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get target for te rule");
        }
    fail:
        return t;
    };
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *cls;
        if (qpol_terule_get_object_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for te rule");
        }
    fail:
        return cls;
    };
    const qpol_type_t *default_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        if (qpol_terule_get_default_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get default for te rule");
        }
    fail:
        return t;
    };

    %exception cond {
        $action
        if (!result) {
            PyErr_SetString(PyExc_AttributeError, "Rule is not conditional.");
            return NULL;
        }
    }
    const qpol_cond_t *cond(qpol_policy_t *p) {
        const qpol_cond_t *c;
        qpol_terule_get_cond(p, self, &c);
        return c;
    };
    int is_enabled(qpol_policy_t *p) {
        uint32_t e;
        if (qpol_terule_get_is_enabled(p, self, &e)) {
            SWIG_exception(SWIG_ValueError, "Could not determine if te rule is enabled");
        }
    fail:
        return (int) e;
    };

    %exception which_list {
        $action
        if (result < 0) {
            PyErr_SetString(PyExc_AttributeError, "Rule is not conditional.");
            return NULL;
        }
    }
    int which_list(qpol_policy_t *p) {
        const qpol_cond_t *c;
        uint32_t which = 0;
        qpol_terule_get_cond(p, self, &c);
        if (c == NULL) {
            return -1;
        } else if (qpol_terule_get_which_list(p, self, &which)) {
            return -1;
        }
        return (int) which;
    };

    %newobject syn_terule_iter(qpol_policy_t*);
    qpol_iterator_t *syn_terule_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_terule_get_syn_terule_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
    fail:
        return iter;
    };
};
%inline %{
    qpol_terule_t *qpol_terule_from_void(void *x) {
        return (qpol_terule_t*)x;
    };
%}

/* qpol conditional */
typedef struct qpol_cond {} qpol_cond_t;
%extend qpol_cond {
    qpol_cond() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_cond_t objects");
    fail:
        return NULL;
    };
    ~qpol_cond() {
        /* no op */
        return;
    };

    %newobject expr_node_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_cond_expr_node_from_void) %}
    qpol_iterator_t *expr_node_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        if (qpol_cond_get_expr_node_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
    fail:
        return iter;
    };

    %newobject av_true_iter(qpol_policy_t*, int);
    qpol_iterator_t *av_true_iter(qpol_policy_t *p, int rule_types) {
        qpol_iterator_t *iter;
        if (qpol_cond_get_av_true_iter(p, self, rule_types, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
    fail:
        return iter;
    };
    %newobject av_false_iter(qpol_policy_t*, int);
    qpol_iterator_t *av_false_iter(qpol_policy_t *p, int rule_types) {
        qpol_iterator_t *iter;
        if (qpol_cond_get_av_false_iter(p, self, rule_types, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
    fail:
        return iter;
    };
    %newobject te_true_iter(qpol_policy_t*, int);
    qpol_iterator_t *te_true_iter(qpol_policy_t *p, int rule_types) {
        qpol_iterator_t *iter;
        if (qpol_cond_get_te_true_iter(p, self, rule_types, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
    fail:
        return iter;
    };
    %newobject te_false_iter(qpol_policy_t*, int);
    qpol_iterator_t *te_false_iter(qpol_policy_t *p, int rule_types) {
        qpol_iterator_t *iter;
        if (qpol_cond_get_te_false_iter(p, self, rule_types, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
    fail:
            return iter;
    };
    int evaluate(qpol_policy_t *p) {
        uint32_t e;
        if (qpol_cond_eval(p, self, &e)) {
            SWIG_exception(SWIG_RuntimeError, "Could not evaluate conditional");
        }
    fail:
        return (int) e;
    };
};
%inline %{
    qpol_cond_t *qpol_cond_from_void(void *x) {
        return (qpol_cond_t*)x;
    };
%}

/* qpol conditional expression node */
#define QPOL_COND_EXPR_BOOL 1      /* plain bool */
#define QPOL_COND_EXPR_NOT  2      /* !bool */
#define QPOL_COND_EXPR_OR   3      /* bool || bool */
#define QPOL_COND_EXPR_AND  4      /* bool && bool */
#define QPOL_COND_EXPR_XOR  5      /* bool ^ bool */
#define QPOL_COND_EXPR_EQ   6      /* bool == bool */
#define QPOL_COND_EXPR_NEQ  7      /* bool != bool */
typedef struct qpol_cond_expr_node {} qpol_cond_expr_node_t;
%extend qpol_cond_expr_node {
    qpol_cond_expr_node() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_cond_expr_node_t objects");
    fail:
        return NULL;
    };
    ~qpol_cond_expr_node() {
        /* no op */
        return;
    };
    int expr_type(qpol_policy_t *p) {
        uint32_t et;
        if (qpol_cond_expr_node_get_expr_type(p, self, &et)) {
            SWIG_exception(SWIG_ValueError, "Could not get node expression type");
        }
    fail:
        return (int) et;
    };
    qpol_bool_t *get_boolean(qpol_policy_t *p) {
        uint32_t et;
        qpol_bool_t *b = NULL;
        qpol_cond_expr_node_get_expr_type(p, self, &et);
        if (et != QPOL_COND_EXPR_BOOL) {
            SWIG_exception(SWIG_TypeError, "Node does not contain a boolean");
        } else if (qpol_cond_expr_node_get_bool(p, self, &b)) {
            SWIG_exception(SWIG_ValueError, "Could not get boolean for node");
        }
    fail:
        return b;
    };
};
%inline %{
    qpol_cond_expr_node_t *qpol_cond_expr_node_from_void(void *x) {
        return (qpol_cond_expr_node_t*)x;
    };
%}

/* qpol filename trans */
typedef struct qpol_filename_trans {} qpol_filename_trans_t;
%extend qpol_filename_trans {
    qpol_filename_trans() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_filename_trans_t objects");
    fail:
        return NULL;
    };
    ~qpol_filename_trans() {
        /* no op */
        return;
    };
    %pythoncode %{
    def rule_type(self,policy):
        return "type_transition"
    %}

    const qpol_type_t *source_type (qpol_policy_t *p) {
        const qpol_type_t *t;
        if (qpol_filename_trans_get_source_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get source for filename transition rule");
        }
    fail:
        return t;
    };
    const qpol_type_t *target_type (qpol_policy_t *p) {
        const qpol_type_t *t;
        if (qpol_filename_trans_get_target_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get target for filename transition rule");       }
    fail:
        return t;
    };
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *cls;
        if (qpol_filename_trans_get_object_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for filename transition rule");        }
    fail:
        return cls;
    };
    const qpol_type_t *default_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        if (qpol_filename_trans_get_default_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get default for filename transition rule");
        }
    fail:
        return t;
    };
    const char *filename(qpol_policy_t *p) {
        const char *name;
        if (qpol_filename_trans_get_filename(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get file for filename transition rule");
        }
    fail:
        return name;
    };

};
%inline %{
    qpol_filename_trans_t *qpol_filename_trans_from_void(void *x) {
        return (qpol_filename_trans_t*)x;
    };
%}

/* qpol polcap */
typedef struct qpol_polcap {} qpol_polcap_t;
%extend qpol_polcap {
    qpol_polcap() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_polcap_t objects");
    fail:
        return NULL;
    };
    ~qpol_polcap() {
        /* no op */
        return;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        if (qpol_polcap_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get polcap name rule");
        }
    fail:
        return name;
    };

};
%inline %{
    qpol_polcap_t *qpol_polcap_from_void(void *x) {
        return (qpol_polcap_t*)x;
    };
%}

/* qpol typebounds */
typedef struct qpol_typebounds {} qpol_typebounds_t;
%extend qpol_typebounds {
    qpol_typebounds() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_typebounds_t objects");
    fail:
        return NULL;
    };
    ~qpol_typebounds() {
        /* no op */
        return;
    };
    const char *parent_name(qpol_policy_t *p) {
        const char *name;
        if (qpol_typebounds_get_parent_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get parent name");
        }
    fail:
        return name;
    };
    const char *child_name(qpol_policy_t *p) {
        const char *name;
        if (qpol_typebounds_get_child_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get child name");
        }
    fail:
        return name;
    };
};
%inline %{
    qpol_typebounds_t *qpol_typebounds_from_void(void *x) {
        return (qpol_typebounds_t*)x;
    };
%}

/* qpol rolebounds */
typedef struct qpol_rolebounds {} qpol_rolebounds_t;
%extend qpol_rolebounds {
    qpol_rolebounds() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_rolebounds_t objects");
    fail:
        return NULL;
    };
    ~qpol_rolebounds() {
        /* no op */
        return;
    };
    const char *parent_name(qpol_policy_t *p) {
        const char *name;
        if (qpol_rolebounds_get_parent_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get parent name");
        }
    fail:
        return name;
    };
    const char *child_name(qpol_policy_t *p) {
        const char *name;
        if (qpol_rolebounds_get_child_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get child name");
        }
    fail:
        return name;
    };
};
%inline %{
    qpol_rolebounds_t *qpol_rolebounds_from_void(void *x) {
        return (qpol_rolebounds_t*)x;
    };
%}

/* qpol userbounds */
typedef struct qpol_userbounds {} qpol_userbounds_t;
%extend qpol_userbounds {
    qpol_userbounds() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_userbounds_t objects");
    fail:
        return NULL;
    };
    ~qpol_userbounds() {
        /* no op */
        return;
    };
    const char *parent_name(qpol_policy_t *p) {
        const char *name;
        if (qpol_userbounds_get_parent_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get parent name");
        }
    fail:
        return name;
    };
    const char *child_name(qpol_policy_t *p) {
        const char *name;
        if (qpol_userbounds_get_child_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get child name");
        }
    fail:
        return name;
    };
};
%inline %{
    qpol_userbounds_t *qpol_userbounds_from_void(void *x) {
        return (qpol_userbounds_t*)x;
    };
%}

/* qpol default_object */
typedef struct qpol_default_object {} qpol_default_object_t;
%extend qpol_default_object {
    qpol_default_object() {
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_default_object_t objects");
    fail:
        return NULL;
    };
    ~qpol_default_object() {
        /* no op */
        return;
    };

    %newobject object_class();
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *cls;
        if (qpol_default_object_get_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get class");
        }
    fail:
        return cls;
    };

    const char *user_default(qpol_policy_t *p) {
        const char *value;
        if (qpol_default_object_get_user_default(p, self, &value)) {
            SWIG_exception(SWIG_ValueError, "Could not get user default");
        }
    fail:
        return value;
    };
    const char *role_default(qpol_policy_t *p) {
        const char *value;
        if (qpol_default_object_get_role_default(p, self, &value)) {
            SWIG_exception(SWIG_ValueError, "Could not get role default");
        }
    fail:
        return value;
    };
    const char *type_default(qpol_policy_t *p) {
        const char *value;
        if (qpol_default_object_get_type_default(p, self, &value)) {
            SWIG_exception(SWIG_ValueError, "Could not get type default");
        }
    fail:
        return value;
    };
    const char *range_default(qpol_policy_t *p) {
        const char *value;
        if (qpol_default_object_get_range_default(p, self, &value)) {
            SWIG_exception(SWIG_ValueError, "Could not get range defaults");
        }
    fail:
        return value;
    };
};
%inline %{
    qpol_default_object_t *qpol_default_object_from_void(void *x) {
        return (qpol_default_object_t*)x;
    };
%}

/* qpol iomemcon */
typedef struct qpol_iomemcon {} qpol_iomemcon_t;
%extend qpol_iomemcon {
    qpol_iomemcon(qpol_policy_t *p, uint64_t low, uint64_t high) {
        const qpol_iomemcon_t *qp;
        if (qpol_policy_get_iomemcon_by_addr(p, low, high, &qp)) {
            SWIG_exception(SWIG_RuntimeError, "iomemcon statement does not exist");
        }
    fail:
        return (qpol_iomemcon_t*)qp;
    };
    ~qpol_iomemcon() {
        /* no op */
        return;
    };
    uint64_t low_addr(qpol_policy_t *p) {
        uint64_t addr = 0;
        if(qpol_iomemcon_get_low_addr(p, self, &addr)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get low addr for iomemcon statement");
        }
    fail:
        return addr;
    };
    uint64_t high_addr(qpol_policy_t *p) {
        uint64_t addr = 0;
        if(qpol_iomemcon_get_high_addr(p, self, &addr)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get high addr for iomemcon statement");
        }
    fail:
        return addr;
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        if (qpol_iomemcon_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get context for iomemcon statement");
        }
    fail:
        return ctx;
    };
}
%inline %{
    qpol_iomemcon_t *qpol_iomemcon_from_void(void *x) {
        return (qpol_iomemcon_t*)x;
    };
%}

/* qpol ioportcon */
typedef struct qpol_ioportcon {} qpol_ioportcon_t;
%extend qpol_ioportcon {
    qpol_ioportcon(qpol_policy_t *p, uint32_t low, uint32_t high) {
        const qpol_ioportcon_t *qp;
        if (qpol_policy_get_ioportcon_by_port(p, low, high, &qp)) {
            SWIG_exception(SWIG_RuntimeError, "ioportcon statement does not exist");
        }
    fail:
        return (qpol_ioportcon_t*)qp;
    };
    ~qpol_ioportcon() {
        /* no op */
        return;
    };
    uint32_t low_port(qpol_policy_t *p) {
        uint32_t port = 0;
        if(qpol_ioportcon_get_low_port(p, self, &port)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get low port for ioportcon statement");
        }
    fail:
        return port;
    };
    uint32_t high_port(qpol_policy_t *p) {
        uint32_t port = 0;
        if(qpol_ioportcon_get_high_port(p, self, &port)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get high port for ioportcon statement");
        }
    fail:
        return port;
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        if (qpol_ioportcon_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get context for ioportcon statement");
        }
    fail:
        return ctx;
    };
}
%inline %{
    qpol_ioportcon_t *qpol_ioportcon_from_void(void *x) {
        return (qpol_ioportcon_t*)x;
    };
%}

/* qpol pcidevicecon */
typedef struct qpol_pcidevicecon {} qpol_pcidevicecon_t;
%extend qpol_pcidevicecon {
	qpol_pcidevicecon() {
		SWIG_exception(SWIG_RuntimeError, "pcidevicecon statement does not exist");
	fail:
		return NULL;
	};
	~qpol_pcidevicecon() {
		return;
	};
    uint32_t device(qpol_policy_t *p) {
        uint32_t device = 0;
        if(qpol_pcidevicecon_get_device(p, self, &device)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get device for pcidevicecon statement");
        }
    fail:
        return device;
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        if (qpol_pcidevicecon_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get context for pcidevicecon statement");
        }
    fail:
        return ctx;
    };
}
%inline %{
    qpol_pcidevicecon_t *qpol_pcidevicecon_from_void(void *x) {
        return (qpol_pcidevicecon_t*)x;
    };
%}

/* qpol pirqcon */
typedef struct qpol_pirqcon {} qpol_pirqcon_t;
%extend qpol_pirqcon {
    qpol_pirqcon() {
        SWIG_exception(SWIG_RuntimeError, "pirqcon statement does not exist");
    fail:
        return NULL;
    };
    ~qpol_pirqcon() {
	return;
    };
    uint32_t irq(qpol_policy_t *p) {
        uint16_t irq = 0;
        if(qpol_pirqcon_get_irq(p, self, &irq)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get irq for pirqcon statement");
        }
    fail:
        return irq;
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        if (qpol_pirqcon_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get context for pirqcon statement");
        }
    fail:
        return ctx;
    };
}
%inline %{
    qpol_pirqcon_t *qpol_pirqcon_from_void(void *x) {
        return (qpol_pirqcon_t*)x;
    };
%}

/* qpol devicetreecon */
typedef struct qpol_devicetreecon {} qpol_devicetreecon_t;
%extend qpol_devicetreecon {
    qpol_devicetreecon() {

        SWIG_exception(SWIG_RuntimeError, "devicetreecon statement does not exist");

    fail:
        return NULL;
    };
    char *path(qpol_policy_t *p) {
        char *path = NULL;
        if(qpol_devicetreecon_get_path(p, self, &path)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get path for devicetreecon statement");
        }
    fail:
        return path;
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        if (qpol_devicetreecon_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get context for devicetreecon statement");
        }
    fail:
        return ctx;
    };
}
%inline %{
    qpol_devicetreecon_t *qpol_devicetreecon_from_void(void *x) {
        return (qpol_devicetreecon_t*)x;
    };
%}

