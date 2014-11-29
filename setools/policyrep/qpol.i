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

/* Provide hooks so that language-specific modules can define the
 * callback function, used by the handler in
 * qpol_policy_open_from_file().
 */
SWIGEXPORT qpol_callback_fn_t qpol_swig_message_callback = NULL;
SWIGEXPORT void * qpol_swig_message_callback_arg = NULL;

%}

%include exception.i
%include stdint.i

%{
#undef BEGIN_EXCEPTION
#undef END_EXCEPTION
%}

/* handle size_t as architecture dependent */
#ifdef SWIGWORDSIZE64
typedef uint64_t size_t;
#else
typedef uint32_t size_t;
#endif
%{
#define BEGIN_EXCEPTION
#define END_EXCEPTION
%}

/* utility functions */
const char *libqpol_get_version(void);

%rename(qpol_default_policy_find) wrap_qpol_default_policy_find;
%newobject wrap_qpol_default_policy_find();

%inline %{
    /* cast void * to char * as it can't have a constructor */
    const char * to_str(void *x) {
        return (const char *)x;
    }

    char * wrap_qpol_default_policy_find(void) {
        char *path;
        int retv;
        BEGIN_EXCEPTION
        retv = qpol_default_policy_find(&path);
        if (retv < 0) {
            SWIG_exception(SWIG_IOError, "Error searching for default policy");
        } else if (retv > 0) {
            SWIG_exception(SWIG_RuntimeError, "Could not find default policy");
        } else {
            return path;
        }
        END_EXCEPTION
    fail: /* SWIG_exception calls goto fail */
        return NULL;
    }
%}

%pythoncode %{
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
%}

/* qpol_module */
#define QPOL_MODULE_UNKNOWN 0
#define QPOL_MODULE_BASE    1
#define QPOL_MODULE_OTHER   2
typedef struct qpol_module {} qpol_module_t;
%extend qpol_module {
    qpol_module(const char *path) {
        qpol_module_t *m;
        BEGIN_EXCEPTION
        if (qpol_module_create_from_file(path, &m)) {
            SWIG_exception(SWIG_IOError, "Error opening module");
        }
        return m;
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_module() {
        qpol_module_destroy(&self);
    };
    const char *path() {
        const char *p;
        BEGIN_EXCEPTION
        if (qpol_module_get_path(self, &p)) {
            SWIG_exception(SWIG_ValueError,"Could not get module path");
        }
        return p;
        END_EXCEPTION
    fail:
        return NULL;
    };
    const char *name() {
        const char *n;
        BEGIN_EXCEPTION
        if (qpol_module_get_name(self, &n)) {
            SWIG_exception(SWIG_ValueError,"Could not get module name");
        }
        return n;
        END_EXCEPTION
    fail:
            return NULL;
    };
    const char *version() {
        const char *v;
        BEGIN_EXCEPTION
        if (qpol_module_get_version(self, &v)) {
            SWIG_exception(SWIG_ValueError,"Could not get module version");
        }
        return v;
        END_EXCEPTION
    fail:
            return NULL;
    };
    int module_type() {
        int t;
        BEGIN_EXCEPTION
        if (qpol_module_get_type(self, &t)) {
            SWIG_exception(SWIG_ValueError,"Could not get module type");
        }
        END_EXCEPTION
    fail:
        return t;
    };
    int enabled() {
        int e;
        BEGIN_EXCEPTION
        if (qpol_module_get_enabled(self, &e)) {
            SWIG_exception(SWIG_ValueError,"Could not get module state");
        }
        END_EXCEPTION
    fail:
            return e;
    };
    void enabled(int state) {
        BEGIN_EXCEPTION
        if (qpol_module_set_enabled(self, state)) {
            SWIG_exception(SWIG_RuntimeError, "Could not set module state");
        }
        END_EXCEPTION
    fail:
        return;
    };
};

/* qpol_policy */
#define QPOL_POLICY_OPTION_NO_NEVERALLOWS 0x00000001
#define QPOL_POLICY_OPTION_NO_RULES       0x00000002
#define QPOL_POLICY_OPTION_MATCH_SYSTEM   0x00000004
typedef struct qpol_policy {} qpol_policy_t;
typedef void (*qpol_callback_fn_t) (void *varg, struct qpol_policy * policy, int level, const char *fmt, va_list va_args);
#define QPOL_POLICY_UNKNOWN       -1
#define QPOL_POLICY_KERNEL_SOURCE  0
#define QPOL_POLICY_KERNEL_BINARY  1
#define QPOL_POLICY_MODULE_BINARY  2
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
    QPOL_CAP_ROLETRANS
} qpol_capability_e;
%exception qpol_policy {
  $action
  if (!result) {
    PyErr_SetFromErrno(PyExc_OSError);
    return NULL;
  }
}
%extend qpol_policy {
    qpol_policy(const char *path, const int options) {
        qpol_policy_t *p;
        qpol_policy_open_from_file(path, &p, qpol_swig_message_callback, qpol_swig_message_callback_arg, options);
        return p;
    }
    ~qpol_policy() {
        qpol_policy_destroy(&self);
    };
    void reevaluate_conditionals() {
        BEGIN_EXCEPTION
        if (qpol_policy_reevaluate_conds(self)) {
            SWIG_exception(SWIG_ValueError, "Error evaluating conditional expressions");
        }
        END_EXCEPTION
    fail:
        return;
    };
    void append_mod(qpol_module_t *mod) {
        BEGIN_EXCEPTION
        if (qpol_policy_append_module(self, mod)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        END_EXCEPTION
    fail:
        return;
    };
    void do_rebuild (const int options) {
        BEGIN_EXCEPTION
        if (qpol_policy_rebuild(self, options)) {
            SWIG_exception(SWIG_RuntimeError, "Failed rebuilding policy");
        }
        END_EXCEPTION
    fail:
        return;
    };
    int version () {
        unsigned int v;
        (void)qpol_policy_get_policy_version(self, &v); /* only error is on null parameters neither can be here */
        return (int) v;
    };

    int handle_unknown () {
        unsigned int h;
        (void)qpol_policy_get_policy_handle_unknown(self, &h);
        return (int) h;
    };

    int policy_type () {
        int t;
        (void)qpol_policy_get_type(self, &t); /* only error is on null parameters neither can be here */
        return t;
    };
    int capability (qpol_capability_e cap) {
        return qpol_policy_has_capability(self, cap);
    };
    void build_syn_rules() {
        BEGIN_EXCEPTION
        if (qpol_policy_build_syn_rule_table(self)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        END_EXCEPTION
    fail:
        return;
    };
    %newobject module_iter();
    qpol_iterator_t *module_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_module_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };
    %newobject type_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_type_from_void) %}
    qpol_iterator_t *type_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_type_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject role_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_role_from_void) %}
    qpol_iterator_t *role_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_role_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject level_iter();
    qpol_iterator_t *level_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_level_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };
    %newobject cat_iter();
    qpol_iterator_t *cat_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_cat_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };
    %newobject user_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_user_from_void) %}
    qpol_iterator_t *user_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_user_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject bool_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_bool_from_void) %}
    qpol_iterator_t *bool_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_bool_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject class_iter(char*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_class_from_void) %}
    qpol_iterator_t *class_iter(char *perm=NULL) {
        BEGIN_EXCEPTION
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
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject common_iter(char*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_common_from_void) %}
    qpol_iterator_t *common_iter(char *perm=NULL) {
        BEGIN_EXCEPTION
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
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject fs_use_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_fs_use_from_void) %}
    qpol_iterator_t *fs_use_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_fs_use_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject genfscon_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_genfscon_from_void) %}
    qpol_iterator_t *genfscon_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_genfscon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject isid_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_isid_from_void) %}
    qpol_iterator_t *isid_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_isid_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject netifcon_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_netifcon_from_void) %}
    qpol_iterator_t *netifcon_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_netifcon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
            return NULL;
    };

    %newobject nodecon_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_nodecon_from_void) %}
    qpol_iterator_t *nodecon_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_nodecon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject portcon_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_portcon_from_void) %}
    qpol_iterator_t *portcon_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_portcon_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject constraint_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_constraint_from_void) %}
    qpol_iterator_t *constraint_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_constraint_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject validatetrans_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_validatetrans_from_void) %}
    qpol_iterator_t *validatetrans_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_validatetrans_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject role_allow_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_role_allow_from_void) %}
    qpol_iterator_t *role_allow_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_role_allow_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject role_trans_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_role_trans_from_void) %}
    qpol_iterator_t *role_trans_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_role_trans_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject range_trans_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_range_trans_from_void) %}
    qpol_iterator_t *range_trans_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_range_trans_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject avrule_iter(int);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_avrule_from_void) %}
    qpol_iterator_t *avrule_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        uint32_t rule_types = QPOL_RULE_ALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT;

        if (qpol_policy_has_capability(self, QPOL_CAP_NEVERALLOW))
            rule_types |= QPOL_RULE_NEVERALLOW;

        if (qpol_policy_get_avrule_iter(self, rule_types, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject terule_iter(int);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_terule_from_void) %}
    qpol_iterator_t *terule_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        uint32_t rule_types = QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER;

        if (qpol_policy_get_terule_iter(self, rule_types, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject cond_iter();
    qpol_iterator_t *cond_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_cond_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };
    %newobject filename_trans_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_filename_trans_from_void) %}
    qpol_iterator_t *filename_trans_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_filename_trans_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject permissive_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_type_from_void) %}
    qpol_iterator_t *permissive_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_permissive_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };

    %newobject typebounds_iter();
    qpol_iterator_t *typebounds_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_typebounds_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };
    %newobject polcap_iter();
    %pythoncode %{ @QpolGenerator(_qpol.qpol_polcap_from_void) %}
    qpol_iterator_t *polcap_iter() {
        BEGIN_EXCEPTION
        qpol_iterator_t *iter;
        if (qpol_policy_get_polcap_iter(self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
    }
        return iter;
        END_EXCEPTION
    fail:
        return NULL;
    };
};

/* qpol iterator */
typedef struct qpol_iterator {} qpol_iterator_t;
%extend qpol_iterator {
    /* user never directly creates, but SWIG expects a constructor */
    qpol_iterator() {
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_TypeError, "User may not create iterators difectly");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_iterator() {
        qpol_iterator_destroy(&self);
    };
    void *item() {
        BEGIN_EXCEPTION
        void *i;
        if (qpol_iterator_get_item(self, &i)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get item");
        }
        return i;
        END_EXCEPTION
    fail:
        return NULL;
    };
    void next_() {
        BEGIN_EXCEPTION
        if (qpol_iterator_next(self)) {
            SWIG_exception(SWIG_RuntimeError, "Error advancing iterator");
        }
        END_EXCEPTION
    fail:
        return;
    };
    int isend() {
        return qpol_iterator_end(self);
    };
    size_t size() {
        BEGIN_EXCEPTION
        size_t s;
        if (qpol_iterator_get_size(self, &s)) {
            SWIG_exception(SWIG_ValueError, "Could not get iterator size");
        }
        return s;
        END_EXCEPTION
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
    fail:
        return NULL;
    };
    ~qpol_type() {
        /* no op */
        return;
    };
    const char *name(qpol_policy_t *p) {
        BEGIN_EXCEPTION
        const char *name;
        if (qpol_type_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get type name");
        }
        return name;
        END_EXCEPTION
    fail:
        return NULL;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        BEGIN_EXCEPTION
        if (qpol_type_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get type value");
        }
        END_EXCEPTION
    fail:
        return (int) v;
    };
    int isalias(qpol_policy_t *p) {
        unsigned char i;
        BEGIN_EXCEPTION
        if (qpol_type_get_isalias(p, self, &i)) {
            SWIG_exception(SWIG_ValueError, "Could not determine whether type is an alias");
        }
        END_EXCEPTION
    fail:
        return (int)i;
    };
    int isattr(qpol_policy_t *p) {
        unsigned char i;
        BEGIN_EXCEPTION
        if (qpol_type_get_isattr(p, self, &i)) {
            SWIG_exception(SWIG_ValueError, "Could not determine whether type is an attribute");
        }
        END_EXCEPTION
    fail:
        return (int)i;
    };
    int ispermissive(qpol_policy_t *p) {
        unsigned char i;
        BEGIN_EXCEPTION
        if (qpol_type_get_ispermissive(p, self, &i)) {
            SWIG_exception(SWIG_ValueError, "Could not determine whether type is permissive");
        }
        END_EXCEPTION
    fail:
        return (int)i;
    };

    %newobject type_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_type_from_void) %}
    qpol_iterator_t *type_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        int retv = qpol_type_get_type_iter(p, self, &iter);
        if (retv < 0) {
            SWIG_exception(SWIG_RuntimeError, "Could not get attribute types");
        } else if (retv > 0) {
            SWIG_exception(SWIG_TypeError, "Type is not an attribute");
        }
        END_EXCEPTION
    fail:
        return iter;
    };

    %newobject attr_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_type_from_void) %}
    qpol_iterator_t *attr_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        int retv = qpol_type_get_attr_iter(p, self, &iter);
        if (retv < 0) {
            SWIG_exception(SWIG_RuntimeError, "Could not get type attributes");
        } else if (retv > 0) {
            SWIG_exception(SWIG_TypeError, "Type is an attribute");
        }
        END_EXCEPTION
    fail:
        return iter;
    };

    %newobject alias_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *alias_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_type_get_alias_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get type aliases");
        }
        END_EXCEPTION
    fail:
        return iter;
    };

    const char *name(qpol_policy_t *p) {
        BEGIN_EXCEPTION
        const char *name;
        if (qpol_permissive_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get permissive type name");
        }
        return name;
        END_EXCEPTION
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
    fail:
        return NULL;
    };
    ~qpol_role() {
        /* no op */
        return;
    };
    int value (qpol_policy_t *p) {
        uint32_t v;
        BEGIN_EXCEPTION
        if (qpol_role_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get role value");
        }
        END_EXCEPTION
    fail:
        return (int) v;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_role_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get role name");
        }
        END_EXCEPTION
        return name;
    fail:
        return NULL;
    };

    %newobject type_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_type_from_void) %}
    qpol_iterator_t *type_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_role_get_type_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get role types");
        }
        END_EXCEPTION
    fail:
        return iter;
    };

    %newobject dominate_iter(qpol_policy_t*);
    qpol_iterator_t *dominate_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_role_get_dominate_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get dominated roles");
        }
        END_EXCEPTION
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
    qpol_level(qpol_policy_t *p, const char *name) {
        const qpol_level_t *l;
        BEGIN_EXCEPTION
        if (qpol_policy_get_level_by_name(p, name, &l)) {
            SWIG_exception(SWIG_RuntimeError, "Level does not exist");
        }
        END_EXCEPTION
        return (qpol_level_t*)l;
    fail:
        return NULL;
    };
    ~qpol_level() {
        /* no op */
        return;
    };
    int isalias(qpol_policy_t *p) {
        unsigned char i;
        BEGIN_EXCEPTION
        if (qpol_level_get_isalias(p, self, &i)) {
            SWIG_exception(SWIG_ValueError, "Could not determine whether level is an alias");
        }
        END_EXCEPTION
    fail:
            return (int)i;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        BEGIN_EXCEPTION
        if (qpol_level_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get level sensitivity value");
        }
        END_EXCEPTION
    fail:
        return (int) v;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_level_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get level sensitivity name");
        }
        END_EXCEPTION
        return name;
    fail:
        return NULL;
    };

    %newobject cat_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_cat_from_void) %}
    qpol_iterator_t *cat_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_level_get_cat_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get level categories");
        }
        END_EXCEPTION
    fail:
        return iter;
    };

    %newobject alias_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *alias_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_level_get_alias_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get level aliases");
        }
        END_EXCEPTION
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
    qpol_cat(qpol_policy_t *p, const char *name) {
        const qpol_cat_t *c;
        BEGIN_EXCEPTION
        if (qpol_policy_get_cat_by_name(p, name, &c)) {
            SWIG_exception(SWIG_RuntimeError, "Category does not exist");
        }
        END_EXCEPTION
        return (qpol_cat_t*)c;
    fail:
        return NULL;
    };
    ~qpol_cat() {
        /* no op */
        return;
    };
    int isalias(qpol_policy_t *p) {
        unsigned char i;
        BEGIN_EXCEPTION
        if (qpol_cat_get_isalias(p, self, &i)) {
            SWIG_exception(SWIG_ValueError, "Could not determine whether category is an alias");
        }
        END_EXCEPTION
    fail:
            return (int)i;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        BEGIN_EXCEPTION
        if (qpol_cat_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get category value");
        }
        END_EXCEPTION
    fail:
        return (int) v;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_cat_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get category name");
        }
        END_EXCEPTION
        return name;
    fail:
        return NULL;
    };
    %newobject alias_iter(qpol_policy_t*);
    qpol_iterator_t *alias_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_cat_get_alias_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get category aliases");
        }
        END_EXCEPTION
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
    qpol_mls_range() {
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_mls_range_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    }
    ~qpol_mls_range() {
        /* no op */
        return;
    };
    const qpol_mls_level_t *high_level(qpol_policy_t *p) {
        const qpol_mls_level_t *l;
        BEGIN_EXCEPTION
        if (qpol_mls_range_get_high_level(p, self, &l)) {
            SWIG_exception(SWIG_ValueError, "Could not get range high levl");
        }
        END_EXCEPTION
    fail:
        return l;
    };
    const qpol_mls_level_t *low_level(qpol_policy_t *p) {
        const qpol_mls_level_t *l;
        BEGIN_EXCEPTION
        if (qpol_mls_range_get_low_level(p, self, &l)) {
            SWIG_exception(SWIG_ValueError, "Could not get range low levl");
        }
        END_EXCEPTION
    fail:
        return l;
    };
};
%inline %{
    qpol_mls_range_t *qpol_mls_range_from_void(void *x) {
        return (qpol_mls_range_t*)x;
    };
%}

/* qpol mls level */
typedef struct qpol_mls_level {} qpol_mls_level_t;
%extend qpol_mls_level {
    qpol_mls_level() {
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_mls_level_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    }
    ~qpol_mls_level() {
        /* no op */
        return;
    };
    const char *sens_name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_mls_level_get_sens_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get level sensitivity name");
        }
        END_EXCEPTION
    fail:
        return name;
    };

    %newobject cat_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_cat_from_void) %}
    qpol_iterator_t *cat_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_mls_level_get_cat_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get level categories");
        }
        END_EXCEPTION
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
    fail:
        return NULL;
    };
    ~qpol_user() {
        /* no op */
        return;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        BEGIN_EXCEPTION
        if (qpol_user_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get user value");
        }
        END_EXCEPTION
    fail:
        return (int) v;
    };

    %newobject role_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_role_from_void) %}
    qpol_iterator_t *role_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_user_get_role_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of Memory");
        }
        END_EXCEPTION
    fail:
        return iter;
    };

    const qpol_mls_range_t *range(qpol_policy_t *p) {
        const qpol_mls_range_t *r;
        BEGIN_EXCEPTION
        if (qpol_user_get_range(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get user range");
        }
        END_EXCEPTION
    fail:
        return r;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_user_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get user name");
        }
        END_EXCEPTION
    fail:
        return name;
    };
    const qpol_mls_level_t *dfltlevel(qpol_policy_t *p) {
        const qpol_mls_level_t *l;
        BEGIN_EXCEPTION
        if (qpol_user_get_dfltlevel(p, self, &l)) {
            SWIG_exception(SWIG_ValueError, "Could not get user default level");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        if (qpol_policy_get_bool_by_name(p, name, &b)) {
            SWIG_exception(SWIG_RuntimeError, "Boolean does not exist");
        }
        END_EXCEPTION
    fail:
        return b;
    };
    ~qpol_bool() {
        /* no op */
        return;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        BEGIN_EXCEPTION
        if (qpol_bool_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get boolean value");
        }
        END_EXCEPTION
    fail:
        return (int) v;
    };
    int state(qpol_policy_t *p) {
        int s;
        BEGIN_EXCEPTION
        if (qpol_bool_get_state(p, self, &s)) {
            SWIG_exception(SWIG_ValueError, "Could not get boolean state");
        }
        END_EXCEPTION
    fail:
        return s;
    };
    void state(qpol_policy_t *p, int state) {
        BEGIN_EXCEPTION
        if (qpol_bool_set_state(p, self, state)) {
            SWIG_exception(SWIG_RuntimeError, "Error setting boolean state");
        }
        END_EXCEPTION
    fail:
        return;
    };
    void set_state_eval(qpol_policy_t *p, int state) {
        BEGIN_EXCEPTION
        if (qpol_bool_set_state_no_eval(p, self, state)) {
            SWIG_exception(SWIG_RuntimeError, "Error setting boolean state");
        }
        END_EXCEPTION
    fail:
        return;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_bool_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get boolean name");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_context_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_context() {
        /* no op */
        return;
    };
     const qpol_user_t *user(qpol_policy_t *p) {
        const qpol_user_t *u;
        BEGIN_EXCEPTION
        if (qpol_context_get_user(p, self, &u)) {
            SWIG_exception(SWIG_ValueError, "Could not get user from context");
        }
        END_EXCEPTION
    fail:
        return u;
     };
     const qpol_role_t *role(qpol_policy_t *p) {
        const qpol_role_t *r;
        BEGIN_EXCEPTION
        if (qpol_context_get_role(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get role from context");
        }
        END_EXCEPTION
    fail:
        return r;
     };
     const qpol_type_t *type_(qpol_policy_t *p) {
        const qpol_type_t *t;
        BEGIN_EXCEPTION
        if (qpol_context_get_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get type from context");
        }
        END_EXCEPTION
    fail:
        return t;
     };
     const qpol_mls_range_t *range(qpol_policy_t *p) {
        const qpol_mls_range_t *r;
        BEGIN_EXCEPTION
        if (qpol_context_get_range(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get range from context");
        }
        END_EXCEPTION
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
    qpol_class(qpol_policy_t *p, const char *name) {
        const qpol_class_t *c;
        BEGIN_EXCEPTION
        if (qpol_policy_get_class_by_name(p, name, &c)) {
            SWIG_exception(SWIG_RuntimeError, "Class does not exist");
        }
        END_EXCEPTION
    fail:
        return (qpol_class_t*)c;
    };
    ~qpol_class() {
        /* no op */
        return;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        BEGIN_EXCEPTION
        if (qpol_class_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get value for class");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        if(qpol_class_get_perm_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get class permissions");
        }
        END_EXCEPTION
    fail:
        return iter;
    };

    %newobject constraint_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_constraint_from_void) %}
    qpol_iterator_t *constraint_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if(qpol_class_get_constraint_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get class constraints");
        }
        END_EXCEPTION
    fail:
        return iter;
    };

    %newobject validatetrans_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_validatetrans_from_void) %}
    qpol_iterator_t *validatetrans_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if(qpol_class_get_validatetrans_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get class validatetrans statements");
        }
        END_EXCEPTION
    fail:
            return iter;
    };

    const char *name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_class_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get class name");
        }
        END_EXCEPTION
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
    qpol_common(qpol_policy_t *p, const char *name) {
        const qpol_common_t *c;
        BEGIN_EXCEPTION
        if (qpol_policy_get_common_by_name(p, name, &c)) {
            SWIG_exception(SWIG_RuntimeError, "Common does not exist");
        }
        END_EXCEPTION
    fail:
        return (qpol_common_t*)c;
    };
    ~qpol_common() {
        /* no op */
        return;
    };
    int value(qpol_policy_t *p) {
        uint32_t v;
        BEGIN_EXCEPTION
        if (qpol_common_get_value(p, self, &v)) {
            SWIG_exception(SWIG_ValueError, "Could not get value for common");
        }
        END_EXCEPTION
    fail:
        return (int) v;
    };

    %newobject perm_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *perm_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if(qpol_common_get_perm_iter(p, self, &iter)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get common permissions");
        }
        END_EXCEPTION
    fail:
        return iter;
    };

    const char *name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_common_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get common name");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        if (qpol_policy_get_fs_use_by_name(p, name, &f)) {
            SWIG_exception(SWIG_RuntimeError, "FS Use Statement does not exist");
        }
        END_EXCEPTION
    fail:
        return (qpol_fs_use_t*)f;
    };
    ~qpol_fs_use() {
        /* no op */
        return;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_fs_use_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get file system name");
        }
        END_EXCEPTION
    fail:
        return name;
    };
    int behavior(qpol_policy_t *p) {
        uint32_t behav;
        BEGIN_EXCEPTION
        if (qpol_fs_use_get_behavior(p, self, &behav)) {
            SWIG_exception(SWIG_ValueError, "Could not get file system labeling behavior");
        }
        END_EXCEPTION
    fail:
        return (int) behav;
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        uint32_t behav;
        const qpol_context_t *ctx = NULL;
        BEGIN_EXCEPTION
        qpol_fs_use_get_behavior(p, self, &behav);
        if (behav == QPOL_FS_USE_PSID) {
            SWIG_exception(SWIG_TypeError, "Cannot get context for fs_use_psid statements");
        } else if (qpol_fs_use_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get file system context");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        if (qpol_policy_get_genfscon_by_name(p, name, path, &g)) {
            SWIG_exception(SWIG_RuntimeError, "Genfscon statement does not exist");
        }
        END_EXCEPTION
    fail:
        return g;
    };
    ~qpol_genfscon() {
        free(self);
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_genfscon_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get file system name");
        }
        END_EXCEPTION
    fail:
        return name;
    };
    const char *path(qpol_policy_t *p) {
        const char *path;
        BEGIN_EXCEPTION
        if (qpol_genfscon_get_path(p, self, &path)) {
            SWIG_exception(SWIG_ValueError, "Could not get file system path");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        if (qpol_genfscon_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get context for genfscon statement");
        }
        END_EXCEPTION
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
    qpol_isid(qpol_policy_t *p, const char *name) {
        const qpol_isid_t *i;
        BEGIN_EXCEPTION
        if (qpol_policy_get_isid_by_name(p, name, &i)) {
            SWIG_exception(SWIG_RuntimeError, "Isid does not exist");
        }
        END_EXCEPTION
    fail:
        return (qpol_isid_t*)i;
    };
    ~qpol_isid() {
        /* no op */
        return;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_isid_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get name for initial sid");
        }
        END_EXCEPTION
    fail:
        return name;
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        BEGIN_EXCEPTION
        if (qpol_isid_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get context for initial sid");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        if (qpol_policy_get_netifcon_by_name(p, name, &n)) {
            SWIG_exception(SWIG_RuntimeError, "Netifcon statement does not exist");
        }
        END_EXCEPTION
    fail:
        return (qpol_netifcon_t*)n;
    };
    ~qpol_netifcon() {
        /* no op */
        return;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_netifcon_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get name for netifcon statement");
        }
        END_EXCEPTION
    fail:
        return name;
    };
    const qpol_context_t *msg_con(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        BEGIN_EXCEPTION
        if (qpol_netifcon_get_msg_con(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get message context for netifcon statement");
        }
        END_EXCEPTION
    fail:
        return ctx;
    };
    const qpol_context_t *if_con(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        BEGIN_EXCEPTION
        if (qpol_netifcon_get_if_con(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get interface context for netifcon statement");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        a[0] = (uint32_t) addr[0]; a[1] = (uint32_t) addr[1];
        a[2] = (uint32_t) addr[2]; a[3] = (uint32_t) addr[3];
        m[0] = (uint32_t) mask[0]; m[1] = (uint32_t) mask[1];
        m[2] = (uint32_t) mask[2]; m[3] = (uint32_t) mask[3];
        if (qpol_policy_get_nodecon_by_node(p, a, m, protocol, &n)) {
            SWIG_exception(SWIG_RuntimeError, "Nodecon statement does not exist");
        }
        END_EXCEPTION
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

        BEGIN_EXCEPTION
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

        END_EXCEPTION
    fail:
        return addr;
    };
    char *mask(qpol_policy_t *p) {
        uint32_t *m;
        unsigned char proto;
        char *mask;
        BEGIN_EXCEPTION
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
        END_EXCEPTION
    fail:
            return mask;
    };
    int protocol(qpol_policy_t *p) {
        unsigned char proto;
        BEGIN_EXCEPTION
        if (qpol_nodecon_get_protocol(p, self, &proto)) {
            SWIG_exception(SWIG_ValueError, "Could not get protocol for nodecon statement");
        }
        END_EXCEPTION
    fail:
        if(proto == QPOL_IPV4) {
            return AF_INET;
        } else {
            return AF_INET6;
        }
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        BEGIN_EXCEPTION
        if (qpol_nodecon_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get context for nodecon statement");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        if (qpol_policy_get_portcon_by_port(p, low, high, protocol, &qp)) {
            SWIG_exception(SWIG_RuntimeError, "Portcon statement does not exist");
        }
        END_EXCEPTION
    fail:
        return (qpol_portcon_t*)qp;
    };
    ~qpol_portcon() {
        /* no op */
        return;
    };
    uint16_t low_port(qpol_policy_t *p) {
        uint16_t port = 0;
        BEGIN_EXCEPTION
        if(qpol_portcon_get_low_port(p, self, &port)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get low port for portcon statement");
        }
        END_EXCEPTION
    fail:
        return port;
    };
    uint16_t high_port(qpol_policy_t *p) {
        uint16_t port = 0;
        BEGIN_EXCEPTION
        if(qpol_portcon_get_high_port(p, self, &port)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get high port for portcon statement");
        }
        END_EXCEPTION
    fail:
        return port;
    };
    uint8_t protocol(qpol_policy_t *p) {
        uint8_t proto = 0;
        BEGIN_EXCEPTION
        if (qpol_portcon_get_protocol(p, self, &proto)) {
            SWIG_exception(SWIG_RuntimeError, "Could not get protocol for portcon statement");
        }
        END_EXCEPTION
    fail:
        return proto;
    };
    const qpol_context_t *context(qpol_policy_t *p) {
        const qpol_context_t *ctx;
        BEGIN_EXCEPTION
        if (qpol_portcon_get_context(p, self, &ctx)) {
            SWIG_exception(SWIG_ValueError, "Could not get context for portcon statement");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_constraint_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_constraint() {
        free(self);
    };
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *cls;
        BEGIN_EXCEPTION
        if (qpol_constraint_get_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for constraint");
        }
        END_EXCEPTION
    fail:
        return cls;
    };

    %newobject perm_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *perm_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_constraint_get_perm_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
    fail:
        return iter;
    };

    %newobject expr_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_constraint_expr_node_from_void) %}
    qpol_iterator_t *expr_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_constraint_get_expr_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_validatetrans_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_validatetrans() {
        free(self);
    };
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *cls;
        BEGIN_EXCEPTION
        if (qpol_validatetrans_get_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for validatetrans");
        }
        END_EXCEPTION
    fail:
        return cls;
    };
    %newobject expr_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.qpol_constraint_expr_node_from_void) %}
    qpol_iterator_t *expr_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_validatetrans_get_expr_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_constraint_expr_node_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_constraint_expr_node() {
        /* no op */
        return;
    };
    int expr_type(qpol_policy_t *p) {
        uint32_t et;
        BEGIN_EXCEPTION
        if (qpol_constraint_expr_node_get_expr_type(p, self, &et)) {
            SWIG_exception(SWIG_ValueError, "Could not get expression type for node");
        }
        END_EXCEPTION
    fail:
        return (int) et;
    };
    int sym_type(qpol_policy_t *p) {
        uint32_t st;
        BEGIN_EXCEPTION
        if (qpol_constraint_expr_node_get_sym_type(p, self, &st)) {
            SWIG_exception(SWIG_ValueError, "Could not get symbol type for node");
        }
        END_EXCEPTION
    fail:
        return (int) st;
    };
    int op(qpol_policy_t *p) {
        uint32_t op;
        BEGIN_EXCEPTION
        if (qpol_constraint_expr_node_get_op(p, self, &op)) {
            SWIG_exception(SWIG_ValueError, "Could not get operator for node");
        }
        END_EXCEPTION
    fail:
        return (int) op;
    };
    %newobject names_iter(qpol_policy_t*);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *names_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_constraint_expr_node_get_names_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_role_allow_t objects");
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        if (qpol_role_allow_get_source_role(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get source for role allow rule");
        }
        END_EXCEPTION
    fail:
        return r;
    };
    const qpol_role_t *target_role(qpol_policy_t *p) {
        const qpol_role_t *r;
        BEGIN_EXCEPTION
        if (qpol_role_allow_get_target_role(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get target for role allow rule");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_role_trans_t objects");
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        if (qpol_role_trans_get_source_role(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get source for role_transition rule");
        }
        END_EXCEPTION
    fail:
        return r;
    };
    const qpol_type_t *target_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        BEGIN_EXCEPTION
        if (qpol_role_trans_get_target_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get target for role_transition rule");
        }
        END_EXCEPTION
    fail:
        return t;
    };
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *c;
        BEGIN_EXCEPTION
        if (qpol_role_trans_get_object_class(p, self, &c)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for role_transition rule");
        }
        END_EXCEPTION
    fail:
        return c;
    };
    const qpol_role_t *default_role(qpol_policy_t *p) {
        const qpol_role_t *r;
        BEGIN_EXCEPTION
        if (qpol_role_trans_get_default_role(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get default for role_transition rule");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_range_trans_t objects");
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        if (qpol_range_trans_get_source_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get source for range_transition rule");
        }
        END_EXCEPTION
    fail:
        return t;
    };
    const qpol_type_t *target_type (qpol_policy_t *p) {
        const qpol_type_t *t;
        BEGIN_EXCEPTION
        if (qpol_range_trans_get_target_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get target for range_transition rule");      }
        END_EXCEPTION
    fail:
        return t;
    };
    const qpol_class_t *target_class(qpol_policy_t *p) {
        const qpol_class_t *cls;
        BEGIN_EXCEPTION
        if (qpol_range_trans_get_target_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for range_transition rule");       }
        END_EXCEPTION
    fail:
        return cls;
    };
    const qpol_mls_range_t *range(qpol_policy_t *p) {
        const qpol_mls_range_t *r;
        BEGIN_EXCEPTION
        if (qpol_range_trans_get_range(p, self, &r)) {
            SWIG_exception(SWIG_ValueError, "Could not get range for range_transition rule");
        }
        END_EXCEPTION
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
#define QPOL_RULE_ALLOW         1
#define QPOL_RULE_NEVERALLOW  128
#define QPOL_RULE_AUDITALLOW    2
#define QPOL_RULE_DONTAUDIT     4
typedef struct qpol_avrule {} qpol_avrule_t;
%extend qpol_avrule {
    qpol_avrule() {
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_avrule_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_avrule() {
        /* no op */
        return;
    };
    const char * rule_type(qpol_policy_t *p) {
        uint32_t rt;
        BEGIN_EXCEPTION
        if (qpol_avrule_get_rule_type(p, self, &rt)) {
            SWIG_exception(SWIG_ValueError, "Could not get rule type for av rule");
        }
        switch (rt) {
            case QPOL_RULE_ALLOW: return "allow"; break;
            case QPOL_RULE_NEVERALLOW: return "neverallow"; break;
            case QPOL_RULE_AUDITALLOW: return "auditallow"; break;
            case QPOL_RULE_DONTAUDIT: return "dontaudit"; break;
        }
        END_EXCEPTION
    fail:
        return NULL;
    };
    const qpol_type_t *source_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        BEGIN_EXCEPTION
        if (qpol_avrule_get_source_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get source for av rule");
        }
        END_EXCEPTION
    fail:
        return t;
    };
    const qpol_type_t *target_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        BEGIN_EXCEPTION
        if (qpol_avrule_get_target_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get target for av rule");
        }
        END_EXCEPTION
    fail:
        return t;
    };
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *cls;
        BEGIN_EXCEPTION
        if (qpol_avrule_get_object_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for av rule");
        }
        END_EXCEPTION
    fail:
        return cls;
    };

    %newobject perm_iter(qpol_policy_t *p);
    %pythoncode %{ @QpolGenerator(_qpol.to_str) %}
    qpol_iterator_t *perm_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_avrule_get_perm_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
    fail:
        return iter;
    };

    %exception cond {
        $action
        if (!result) {
            PyErr_SetString(PyExc_ValueError, "Rule is not conditional.");
            return NULL;
        }
    }
    const qpol_cond_t *cond(qpol_policy_t *p) {
        const qpol_cond_t *c;
        if (qpol_avrule_get_cond(p, self, &c)) {
            SWIG_exception(SWIG_ValueError, "Could not get conditional for av rule");
        }
    fail:
        return c;
    };
    int is_enabled(qpol_policy_t *p) {
        uint32_t e;
        BEGIN_EXCEPTION
        if (qpol_avrule_get_is_enabled(p, self, &e)) {
            SWIG_exception(SWIG_ValueError, "Could not determine if av rule is enabled");
        }
        END_EXCEPTION
    fail:
        return (int) e;
    };
    int which_list(qpol_policy_t *p) {
        const qpol_cond_t *c;
        uint32_t which = 0;
        BEGIN_EXCEPTION
        qpol_avrule_get_cond(p, self, &c);
        if (c == NULL) {
            SWIG_exception(SWIG_TypeError, "Rule is not conditional");
        } else if (qpol_avrule_get_which_list(p, self, &which)) {
            SWIG_exception(SWIG_ValueError, "Could not get conditional list for av rule");
        }
        END_EXCEPTION
    fail:
        return (int) which;
    };
    %newobject syn_avrule_iter(qpol_policy_t*);
    qpol_iterator_t *syn_avrule_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_avrule_get_syn_avrule_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_terule_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_terule() {
        /* no op */
        return;
    };
    const char * rule_type(qpol_policy_t *p) {
        uint32_t rt;
        BEGIN_EXCEPTION
        if (qpol_terule_get_rule_type(p, self, &rt)) {
            SWIG_exception(SWIG_ValueError, "Could not get rule type for te rule");
        }
        switch (rt) {
            case QPOL_RULE_TYPE_TRANS: return "type_transition"; break;
            case QPOL_RULE_TYPE_CHANGE: return "type_change"; break;
            case QPOL_RULE_TYPE_MEMBER: return "type_member"; break;
        }
        END_EXCEPTION
    fail:
        return NULL;
    };
    const qpol_type_t *source_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        BEGIN_EXCEPTION
        if (qpol_terule_get_source_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get source for te rule");
        }
        END_EXCEPTION
    fail:
        return t;
    };
    const qpol_type_t *target_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        BEGIN_EXCEPTION
        if (qpol_terule_get_target_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get target for te rule");
        }
        END_EXCEPTION
    fail:
        return t;
    };
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *cls;
        BEGIN_EXCEPTION
        if (qpol_terule_get_object_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for te rule");
        }
        END_EXCEPTION
    fail:
        return cls;
    };
    const qpol_type_t *default_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        BEGIN_EXCEPTION
        if (qpol_terule_get_default_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get default for te rule");
        }
        END_EXCEPTION
    fail:
        return t;
    };

    %exception cond {
        $action
        if (!result) {
            PyErr_SetString(PyExc_ValueError, "Rule is not conditional.");
            return NULL;
        }
    }
    const qpol_cond_t *cond(qpol_policy_t *p) {
        const qpol_cond_t *c;
        if (qpol_terule_get_cond(p, self, &c)) {
            SWIG_exception(SWIG_ValueError, "Could not get conditional for te rule");
        }
    fail:
        return c;
    };
    int is_enabled(qpol_policy_t *p) {
        uint32_t e;
        BEGIN_EXCEPTION
        if (qpol_terule_get_is_enabled(p, self, &e)) {
            SWIG_exception(SWIG_ValueError, "Could not determine if te rule is enabled");
        }
        END_EXCEPTION
    fail:
        return (int) e;
    };
    int which_list(qpol_policy_t *p) {
        const qpol_cond_t *c;
        uint32_t which = 0;
        BEGIN_EXCEPTION
        qpol_terule_get_cond(p, self, &c);
        if (c == NULL) {
            SWIG_exception(SWIG_TypeError, "Rule is not conditional");
        } else if (qpol_terule_get_which_list(p, self, &which)) {
            SWIG_exception(SWIG_ValueError, "Could not get conditional list for te rule");
        }
        END_EXCEPTION
    fail:
        return (int) which;
    };
    %newobject syn_terule_iter(qpol_policy_t*);
    qpol_iterator_t *syn_terule_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_terule_get_syn_terule_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_cond_t objects");
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        if (qpol_cond_get_expr_node_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
    fail:
        return iter;
    };

    %newobject av_true_iter(qpol_policy_t*, int);
    qpol_iterator_t *av_true_iter(qpol_policy_t *p, int rule_types) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_cond_get_av_true_iter(p, self, rule_types, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
    fail:
        return iter;
    };
    %newobject av_false_iter(qpol_policy_t*, int);
    qpol_iterator_t *av_false_iter(qpol_policy_t *p, int rule_types) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_cond_get_av_false_iter(p, self, rule_types, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
    fail:
        return iter;
    };
    %newobject te_true_iter(qpol_policy_t*, int);
    qpol_iterator_t *te_true_iter(qpol_policy_t *p, int rule_types) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_cond_get_te_true_iter(p, self, rule_types, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
    fail:
        return iter;
    };
    %newobject te_false_iter(qpol_policy_t*, int);
    qpol_iterator_t *te_false_iter(qpol_policy_t *p, int rule_types) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_cond_get_te_false_iter(p, self, rule_types, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
    fail:
            return iter;
    };
    int evaluate(qpol_policy_t *p) {
        uint32_t e;
        BEGIN_EXCEPTION
        if (qpol_cond_eval(p, self, &e)) {
            SWIG_exception(SWIG_RuntimeError, "Could not evaluate conditional");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_cond_expr_node_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_cond_expr_node() {
        /* no op */
        return;
    };
    int expr_type(qpol_policy_t *p) {
        uint32_t et;
        BEGIN_EXCEPTION
        if (qpol_cond_expr_node_get_expr_type(p, self, &et)) {
            SWIG_exception(SWIG_ValueError, "Could not get node expression type");
        }
        END_EXCEPTION
    fail:
        return (int) et;
    };
    qpol_bool_t *get_boolean(qpol_policy_t *p) {
        uint32_t et;
        qpol_bool_t *b = NULL;
        BEGIN_EXCEPTION
        qpol_cond_expr_node_get_expr_type(p, self, &et);
        if (et != QPOL_COND_EXPR_BOOL) {
            SWIG_exception(SWIG_TypeError, "Node does not contain a boolean");
        } else if (qpol_cond_expr_node_get_bool(p, self, &b)) {
            SWIG_exception(SWIG_ValueError, "Could not get boolean for node");
        }
        END_EXCEPTION
    fail:
        return b;
    };
};
%inline %{
    qpol_cond_expr_node_t *qpol_cond_expr_node_from_void(void *x) {
        return (qpol_cond_expr_node_t*)x;
    };
%}

/* qpol type set */
typedef struct qpol_type_set {} qpol_type_set_t;
%extend qpol_type_set {
    qpol_type_set() {
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_type_set_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_type_set() {
        /* no op */
        return;
    };
    %newobject included_types_iter(qpol_policy_t*);
    qpol_iterator_t *included_types_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_type_set_get_included_types_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
    fail:
        return iter;
    };
    %newobject subtracted_types_iter(qpol_policy_t*);
    qpol_iterator_t *subtracted_types_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_type_set_get_subtracted_types_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
    fail:
        return iter;
    };
    int is_star(qpol_policy_t *p) {
        uint32_t s;
        BEGIN_EXCEPTION
        if (qpol_type_set_get_is_star(p, self, &s)) {
            SWIG_exception(SWIG_ValueError, "Could not determine if type set contains star");
        }
        END_EXCEPTION
    fail:
        return (int) s;
    };
    int is_comp(qpol_policy_t *p) {
        uint32_t c;
        BEGIN_EXCEPTION
        if (qpol_type_set_get_is_comp(p, self, &c)) {
            SWIG_exception(SWIG_ValueError, "Could not determine if type set is complemented");
        }
        END_EXCEPTION
    fail:
        return (int) c;
    };
};
%inline %{
    qpol_type_set_t *qpol_type_set_from_void(void *x) {
        return (qpol_type_set_t*)x;
    };
%}

/* qpol syn av rule */
typedef struct qpol_syn_avrule {} qpol_syn_avrule_t;
%extend qpol_syn_avrule {
    qpol_syn_avrule() {
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_syn_avrule_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_syn_avrule() {
        /* no op */
        return;
    };
    int rule_type(qpol_policy_t *p) {
        uint32_t rt;
        BEGIN_EXCEPTION
        if (qpol_syn_avrule_get_rule_type(p, self, &rt)) {
            SWIG_exception(SWIG_ValueError, "Could not get rule type for syn av rule");
        }
        END_EXCEPTION
    fail:
        return (int) rt;
    };
    const qpol_type_set_t *source_type_set(qpol_policy_t *p) {
        const qpol_type_set_t *ts;
        BEGIN_EXCEPTION
        if (qpol_syn_avrule_get_source_type_set(p, self, &ts)) {
            SWIG_exception(SWIG_ValueError, "Could not get source type set for syn av rule");
        }
        END_EXCEPTION
    fail:
        return ts;
    };
    const qpol_type_set_t *target_type_set(qpol_policy_t *p) {
        const qpol_type_set_t *ts;
        BEGIN_EXCEPTION
        if (qpol_syn_avrule_get_target_type_set(p, self, &ts)) {
            SWIG_exception(SWIG_ValueError, "Could not get target type set for syn av rule");
        }
        END_EXCEPTION
    fail:
        return ts;
    };
    int is_target_self(qpol_policy_t *p) {
        uint32_t i;
        BEGIN_EXCEPTION
        if (qpol_syn_avrule_get_is_target_self(p, self, &i)) {
            SWIG_exception(SWIG_ValueError, "Could not determine if target is self for syn av rule");
        }
        END_EXCEPTION
    fail:
        return (int) i;
    };
    %newobject class_iter(qpol_policy_t*);
    qpol_iterator_t *class_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_syn_avrule_get_class_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
    fail:
        return iter;
    };
    %newobject perm_iter(qpol_policy_t*);
    qpol_iterator_t *perm_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_syn_avrule_get_perm_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
    fail:
        return iter;
    };
    long lineno(qpol_policy_t *p) {
        unsigned long l;
        BEGIN_EXCEPTION
        if (qpol_syn_avrule_get_lineno(p, self, &l)) {
            SWIG_exception(SWIG_ValueError, "Could not get line number for syn av rule");
        }
        END_EXCEPTION
    fail:
        return (long)l;
    };
    const qpol_cond_t *cond(qpol_policy_t *p) {
        const qpol_cond_t *c;
        BEGIN_EXCEPTION
        if (qpol_syn_avrule_get_cond(p, self, &c)) {
            SWIG_exception(SWIG_ValueError, "Could not get conditional for syn av rule");
        }
        END_EXCEPTION
    fail:
        return c;
    };
    int is_enabled(qpol_policy_t *p) {
        uint32_t e;
        BEGIN_EXCEPTION
        if (qpol_syn_avrule_get_is_enabled(p, self, &e)) {
            SWIG_exception(SWIG_ValueError, "Could not determine if syn av rule is enabled");
        }
        END_EXCEPTION
    fail:
        return e;
    };
};
%inline %{
    qpol_syn_avrule_t *qpol_syn_avrule_from_void(void *x) {
        return (qpol_syn_avrule_t*)x;
    };
%}

/* qpol syn te rule */
typedef struct qpol_syn_terule {} qpol_syn_terule_t;
%extend qpol_syn_terule {
    qpol_syn_terule() {
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_syn_terule_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_syn_terule() {
        /* no op */
        return;
    };
    int rule_type(qpol_policy_t *p) {
        uint32_t rt;
        BEGIN_EXCEPTION
        if (qpol_syn_terule_get_rule_type(p, self, &rt)) {
            SWIG_exception(SWIG_ValueError, "Could not get rule type for syn te rule");
        }
        END_EXCEPTION
    fail:
        return rt;
    };
    const qpol_type_set_t *source_type_set(qpol_policy_t *p) {
        const qpol_type_set_t *ts;
        BEGIN_EXCEPTION
        if (qpol_syn_terule_get_source_type_set(p, self, &ts)) {
            SWIG_exception(SWIG_ValueError, "Could not get source type set for syn te rule");
        }
        END_EXCEPTION
    fail:
        return ts;
    };
    const qpol_type_set_t *target_type_set(qpol_policy_t *p) {
        const qpol_type_set_t *ts;
        BEGIN_EXCEPTION
        if (qpol_syn_terule_get_target_type_set(p, self, &ts)) {
            SWIG_exception(SWIG_ValueError, "Could not get target type set for syn te rule");
        }
        END_EXCEPTION
    fail:
        return ts;
    };
    %newobject class_iter(qpol_policy_t*);
    qpol_iterator_t *class_iter(qpol_policy_t *p) {
        qpol_iterator_t *iter;
        BEGIN_EXCEPTION
        if (qpol_syn_terule_get_class_iter(p, self, &iter)) {
            SWIG_exception(SWIG_MemoryError, "Out of memory");
        }
        END_EXCEPTION
    fail:
            return iter;
    };
    const qpol_type_t *default_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        BEGIN_EXCEPTION
        if (qpol_syn_terule_get_default_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get default type for syn te rule");
        }
        END_EXCEPTION
    fail:
        return t;
    };
    long lineno(qpol_policy_t *p) {
        unsigned long l;
        BEGIN_EXCEPTION
        if (qpol_syn_terule_get_lineno(p, self, &l)) {
            SWIG_exception(SWIG_ValueError, "Could not get line number for syn te rule");
        }
        END_EXCEPTION
    fail:
        return (long)l;
    };
    const qpol_cond_t *cond(qpol_policy_t *p) {
        const qpol_cond_t *c;
        BEGIN_EXCEPTION
        if (qpol_syn_terule_get_cond(p, self, &c)) {
            SWIG_exception(SWIG_ValueError, "Could not get conditional for syn te rule");
        }
        END_EXCEPTION
    fail:
        return c;
    };
    int is_enabled(qpol_policy_t *p) {
        uint32_t e;
        BEGIN_EXCEPTION
        if (qpol_syn_terule_get_is_enabled(p, self, &e)) {
            SWIG_exception(SWIG_ValueError, "Could not determine if syn te rule is enabled");
        }
        END_EXCEPTION
    fail:
        return (int) e;
    };
};
%inline %{
    qpol_syn_terule_t *qpol_syn_terule_from_void(void *x) {
        return (qpol_syn_terule_t*)x;
    };
%}

/* qpol filename trans */
typedef struct qpol_filename_trans {} qpol_filename_trans_t;
%extend qpol_filename_trans {
    qpol_filename_trans() {
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_filename_trans_t objects");
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        if (qpol_filename_trans_get_source_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get source for filename transition rule");
        }
        END_EXCEPTION
    fail:
        return t;
    };
    const qpol_type_t *target_type (qpol_policy_t *p) {
        const qpol_type_t *t;
        BEGIN_EXCEPTION
        if (qpol_filename_trans_get_target_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get target for filename transition rule");       }
        END_EXCEPTION
    fail:
        return t;
    };
    const qpol_class_t *object_class(qpol_policy_t *p) {
        const qpol_class_t *cls;
        BEGIN_EXCEPTION
        if (qpol_filename_trans_get_object_class(p, self, &cls)) {
            SWIG_exception(SWIG_ValueError, "Could not get class for filename transition rule");        }
        END_EXCEPTION
    fail:
        return cls;
    };
    const qpol_type_t *default_type(qpol_policy_t *p) {
        const qpol_type_t *t;
        BEGIN_EXCEPTION
        if (qpol_filename_trans_get_default_type(p, self, &t)) {
            SWIG_exception(SWIG_ValueError, "Could not get default for filename transition rule");
        }
        END_EXCEPTION
    fail:
        return t;
    };
    const char *filename(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_filename_trans_get_filename(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get file for filename transition rule");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_polcap_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_polcap() {
        /* no op */
        return;
    };
    const char *name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_polcap_get_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get polcap name rule");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_typebounds_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_typebounds() {
        /* no op */
        return;
    };
    const char *parent_name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_typebounds_get_parent_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get parent name");
        }
        END_EXCEPTION
    fail:
        return name;
    };
    const char *child_name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_typebounds_get_child_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get child name");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_rolebounds_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_rolebounds() {
        /* no op */
        return;
    };
    const char *parent_name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_rolebounds_get_parent_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get parent name");
        }
        END_EXCEPTION
    fail:
        return name;
    };
    const char *child_name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_rolebounds_get_child_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get child name");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_userbounds_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_userbounds() {
        /* no op */
        return;
    };
    const char *parent_name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_userbounds_get_parent_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get parent name");
        }
        END_EXCEPTION
    fail:
        return name;
    };
    const char *child_name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_userbounds_get_child_name(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get child name");
        }
        END_EXCEPTION
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
        BEGIN_EXCEPTION
        SWIG_exception(SWIG_RuntimeError, "Cannot directly create qpol_default_object_t objects");
        END_EXCEPTION
    fail:
        return NULL;
    };
    ~qpol_default_object() {
        /* no op */
        return;
    };
    const char *class_name(qpol_policy_t *p) {
        const char *name;
        BEGIN_EXCEPTION
        if (qpol_default_object_get_class(p, self, &name)) {
            SWIG_exception(SWIG_ValueError, "Could not get class name");
        }
        END_EXCEPTION
    fail:
        return name;
    };
    const char *user_default(qpol_policy_t *p) {
        const char *value;
        BEGIN_EXCEPTION
        if (qpol_default_object_get_user_default(p, self, &value)) {
            SWIG_exception(SWIG_ValueError, "Could not get user default");
        }
        END_EXCEPTION
    fail:
        return value;
    };
    const char *role_default(qpol_policy_t *p) {
        const char *value;
        BEGIN_EXCEPTION
        if (qpol_default_object_get_role_default(p, self, &value)) {
            SWIG_exception(SWIG_ValueError, "Could not get role default");
        }
        END_EXCEPTION
    fail:
        return value;
    };
    const char *type_default(qpol_policy_t *p) {
        const char *value;
        BEGIN_EXCEPTION
        if (qpol_default_object_get_type_default(p, self, &value)) {
            SWIG_exception(SWIG_ValueError, "Could not get type default");
        }
        END_EXCEPTION
    fail:
        return value;
    };
    const char *range_default(qpol_policy_t *p) {
        const char *value;
        BEGIN_EXCEPTION
        if (qpol_default_object_get_range_default(p, self, &value)) {
            SWIG_exception(SWIG_ValueError, "Could not get range defaults");
        }
        END_EXCEPTION
    fail:
        return value;
    };
};
%inline %{
    qpol_default_object_t *qpol_default_object_from_void(void *x) {
        return (qpol_default_object_t*)x;
    };
%}
// vim:ft=c noexpandtab
