# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

# Directly use libselinux rather than the Python bindings, since
# only a few functions are needed.

cdef extern from "<selinux/selinux.h>":
    bint selinuxfs_exists()
    const char* selinux_current_policy_path()
    const char* selinux_binary_policy_path()
    char* selinux_boolean_sub(const char *boolean_name);
