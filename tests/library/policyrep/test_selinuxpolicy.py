# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#

import copy

import pytest
import setools


@pytest.mark.obj_args("tests/library/policyrep/selinuxpolicy.conf")
class TestSELinuxPolicy:

    def test_open_policy_non_existant(self) -> None:
        """SELinuxPolicy: Non existant policy on open."""
        with pytest.raises(OSError):
            setools.SELinuxPolicy("tests/policyrep/DOES_NOT_EXIST")

    def test_deepcopy(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: Deep copy"""
        p = copy.deepcopy(compiled_policy)
        assert p is compiled_policy

    def test_handle_unknown(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: handle unknown setting."""
        assert compiled_policy.handle_unknown == setools.HandleUnknown.reject

    def test_mls(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: MLS status."""
        assert compiled_policy.mls

    def test_version(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: version."""
        assert compiled_policy.version

    def test_allow_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: allow count"""
        assert compiled_policy.allow_count == 113

    def test_auditallow_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: auditallow count"""
        assert compiled_policy.auditallow_count == 109

    def test_boolean_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: Boolean count."""
        assert compiled_policy.boolean_count == 127

    # def test_bounds_count(self, compiled_policy: setools.SELinuxPolicy) -> None:

    def test_category_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: category count"""
        assert compiled_policy.category_count == 17

    def test_class_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: object class count"""
        assert compiled_policy.class_count == 7

    def test_common_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: common permisison set count"""
        assert compiled_policy.common_count == 3

    def test_conditional_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: conditional (expression) count"""
        assert compiled_policy.conditional_count == 67

    def test_constraint_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: standard constraint count"""
        assert compiled_policy.constraint_count == 19

    # def test_default_count(self, compiled_policy: setools.SELinuxPolicy) -> None:

    def test_dontaudit_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: dontaudit rule count"""
        assert compiled_policy.dontaudit_count == 107

    def test_fs_use_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: fs_use_* count"""
        assert compiled_policy.fs_use_count == 149

    def test_genfscon_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: genfscon count"""
        assert compiled_policy.genfscon_count == 151

    def test_initial_sid_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: initial sid count"""
        assert compiled_policy.initialsids_count == 11

    def test_level_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: MLS level count"""
        assert compiled_policy.level_count == 13

    def test_mls_constraint_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: MLS constraint count"""
        assert compiled_policy.mlsconstraint_count == 23

    def test_mls_validatetrans_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: MLS validatetrans count"""
        assert compiled_policy.mlsvalidatetrans_count == 3

    def test_netifcon_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: netifcon count"""
        assert compiled_policy.netifcon_count == 167

    def test_neverallow_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: neverallow rule count"""
        # changed after dropping source policy support
        # assert compiled_policy.neverallow_count == 103)
        assert compiled_policy.neverallow_count == 0

    def test_nodecon_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: nodecon count"""
        assert compiled_policy.nodecon_count == 173

    def test_permission_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: permission count"""
        assert compiled_policy.permission_count == 29

    def test_permissive_types_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: permissive types count"""
        assert compiled_policy.permissives_count == 73

    def test_polcap_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: policy capability count"""
        assert compiled_policy.polcap_count == 2

    def test_portcon_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: portcon count"""
        assert compiled_policy.portcon_count == 163

    def test_range_transition_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: range_transition count"""
        assert compiled_policy.range_transition_count == 71

    def test_role_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: role count"""
        assert compiled_policy.role_count == 131

    # def test_role_attribute_count(self, compiled_policy: setools.SELinuxPolicy) -> None:

    def test_role_allow_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: (role) allow count"""
        assert compiled_policy.role_allow_count == 83

    def test_role_transition_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: role_transition count"""
        assert compiled_policy.role_transition_count == 79

    def test_type_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: type count"""
        assert compiled_policy.type_count == 137

    def test_type_attribute_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: type attribute count"""
        assert compiled_policy.type_attribute_count == 157

    def test_type_change_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: type_change rule count"""
        assert compiled_policy.type_change_count == 89

    def test_type_member_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: type_member rule count"""
        assert compiled_policy.type_member_count == 61

    def test_type_transition_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: type_transition rule count"""
        assert compiled_policy.type_transition_count == 97

    def test_user_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: user count"""
        assert compiled_policy.user_count == 101

    def test_validatetrans_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: validatetrans count"""
        assert compiled_policy.validatetrans_count == 5

    def test_allowxperm_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: allowxperm rount"""
        assert compiled_policy.allowxperm_count == 179

    def test_auditallowxperm_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: auditallowxperm rount"""
        assert compiled_policy.auditallowxperm_count == 181

    def test_neverallowxperm_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: neverallowxperm rount"""
        # changed after dropping source policy support
        # assert compiled_policy.neverallowxperm_count == 191)
        assert compiled_policy.neverallowxperm_count == 0

    def test_dontauditxperm_count(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """SELinuxPolicy: dontauditxperm rount"""
        assert compiled_policy.dontauditxperm_count == 193
