# Copyright 2015, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SETools.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import print_function
import copy
import os
import sys
import subprocess
import tempfile
import unittest

from setools import SELinuxPolicy
from setools.policyrep.exception import InvalidPolicy


class SELinuxPolicyTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # create a temp file for the binary policy
        # and then have checkpolicy overwrite it.
        fd, cls.policy_path = tempfile.mkstemp()
        os.close(fd)

        try:
            command = [os.environ['CHECKPOLICY']]
        except KeyError:
            command = ["/usr/bin/checkpolicy"]

        command.extend(["-M", "-o", cls.policy_path, "-U", "reject",
                        "tests/policyrep/selinuxpolicy.conf"])

        with open(os.devnull, "w") as null:
            subprocess.check_call(command, stdout=null, shell=False, close_fds=True)

        try:
            cls.p = SELinuxPolicy("tests/policyrep/selinuxpolicy.conf")
            cls.p_binary = SELinuxPolicy(cls.policy_path)
        except:
            # This should never be hit, since this policy
            # successfully compiled with checkpolicy above.
            # If we do, clean up the binary policy since
            # tearDownClass() does not run.
            os.unlink(cls.policy_path)
            raise

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.policy_path)

    @unittest.skip("Retired for the SELinuxPolicyLoadError test suite.")
    def test_001_open_policy_error(self):
        """SELinuxPolicy: Invalid policy on open."""
        self.assertRaises(InvalidPolicy, SELinuxPolicy, "tests/policyrep/selinuxpolicy-bad.conf")
        sys.stderr.write(
            "The \"category can not be associated\" error above is expected.")

    def test_002_open_policy_non_existant(self):
        """SELinuxPolicy: Non existant policy on open."""
        self.assertRaises(OSError, SELinuxPolicy, "tests/policyrep/DOES_NOT_EXIST")

    def test_003_deepcopy(self):
        """SELinuxPolicy: Deep copy"""
        p = copy.deepcopy(self.p)
        self.assertIs(self.p.policy, p.policy)
        self.assertIs(self.p.filename, p.filename)

    def test_010_handle_unknown(self):
        """SELinuxPolicy: handle unknown setting."""
        self.assertEqual(self.p_binary.handle_unknown, "reject")

    def test_011_mls(self):
        """SELinuxPolicy: MLS status."""
        self.assertTrue(self.p.mls)

    def test_012_version(self):
        """SELinuxPolicy: version."""
        self.assertTrue(self.p.version)

    def test_100_allow_count(self):
        """SELinuxPolicy: allow count"""
        self.assertEqual(self.p.allow_count, 113)

    def test_101_auditallow_count(self):
        """SELinuxPolicy: auditallow count"""
        self.assertEqual(self.p.auditallow_count, 109)

    def test_102_boolean_count(self):
        """SELinuxPolicy: Boolean count."""
        self.assertEqual(self.p.boolean_count, 127)

    # def test_103_bounds_count(self):

    def test_104_category_count(self):
        """SELinuxPolicy: category count"""
        self.assertEqual(self.p.category_count, 17)

    def test_105_class_count(self):
        """SELinuxPolicy: object class count"""
        self.assertEqual(self.p.class_count, 7)

    def test_106_common_count(self):
        """SELinuxPolicy: common permisison set count"""
        self.assertEqual(self.p.common_count, 3)

    def test_107_conditional_count(self):
        """SELinuxPolicy: conditional (expression) count"""
        self.assertEqual(self.p.conditional_count, 67)

    def test_108_constraint_count(self):
        """SELinuxPolicy: standard constraint count"""
        self.assertEqual(self.p.constraint_count, 19)

    # def test_109_default_count(self):

    def test_110_dontaudit_count(self):
        """SELinuxPolicy: dontaudit rule count"""
        self.assertEqual(self.p.dontaudit_count, 107)

    def test_111_fs_use_count(self):
        """SELinuxPolicy: fs_use_* count"""
        self.assertEqual(self.p.fs_use_count, 149)

    def test_112_genfscon_count(self):
        """SELinuxPolicy: genfscon count"""
        self.assertEqual(self.p.genfscon_count, 151)

    def test_113_initial_sid_count(self):
        """SELinuxPolicy: initial sid count"""
        self.assertEqual(self.p.initialsids_count, 11)

    def test_114_level_count(self):
        """SELinuxPolicy: MLS level count"""
        self.assertEqual(self.p.level_count, 13)

    def test_115_mls_constraint_count(self):
        """SELinuxPolicy: MLS constraint count"""
        self.assertEqual(self.p.mlsconstraint_count, 23)

    def test_116_mls_validatetrans_count(self):
        """SELinuxPolicy: MLS validatetrans count"""
        self.assertEqual(self.p.mlsvalidatetrans_count, 3)

    def test_117_netifcon_count(self):
        """SELinuxPolicy: netifcon count"""
        self.assertEqual(self.p.netifcon_count, 167)

    def test_118_neverallow_count(self):
        """SELinuxPolicy: neverallow rule count"""
        self.assertEqual(self.p.neverallow_count, 103)
        self.assertEqual(self.p_binary.neverallow_count, 0)

    def test_119_nodecon_count(self):
        """SELinuxPolicy: nodecon count"""
        self.assertEqual(self.p.nodecon_count, 173)

    def test_120_permission_count(self):
        """SELinuxPolicy: permission count"""
        self.assertEqual(self.p.permission_count, 29)

    def test_121_permissive_types_count(self):
        """SELinuxPolicy: permissive types count"""
        self.assertEqual(self.p.permissives_count, 73)

    def test_122_polcap_count(self):
        """SELinuxPolicy: policy capability count"""
        self.assertEqual(self.p.polcap_count, 2)

    def test_123_portcon_count(self):
        """SELinuxPolicy: portcon count"""
        self.assertEqual(self.p.portcon_count, 163)

    def test_124_range_transition_count(self):
        """SELinuxPolicy: range_transition count"""
        self.assertEqual(self.p.range_transition_count, 71)

    def test_125_role_count(self):
        """SELinuxPolicy: role count"""
        self.assertEqual(self.p.role_count, 131)

    # def test_126_role_attribute_count(self):

    def test_127_role_allow_count(self):
        """SELinuxPolicy: (role) allow count"""
        self.assertEqual(self.p.role_allow_count, 83)

    def test_128_role_transition_count(self):
        """SELinuxPolicy: role_transition count"""
        self.assertEqual(self.p.role_transition_count, 79)

    def test_129_type_count(self):
        """SELinuxPolicy: type count"""
        self.assertEqual(self.p.type_count, 137)

    def test_130_type_attribute_count(self):
        """SELinuxPolicy: type attribute count"""
        self.assertEqual(self.p.type_attribute_count, 157)

    def test_131_type_change_count(self):
        """SELinuxPolicy: type_change rule count"""
        self.assertEqual(self.p.type_change_count, 89)

    def test_132_type_member_count(self):
        """SELinuxPolicy: type_member rule count"""
        self.assertEqual(self.p.type_member_count, 61)

    def test_133_type_transition_count(self):
        """SELinuxPolicy: type_transition rule count"""
        self.assertEqual(self.p.type_transition_count, 97)

    def test_134_user_count(self):
        """SELinuxPolicy: user count"""
        self.assertEqual(self.p.user_count, 101)

    def test_135_validatetrans_count(self):
        """SELinuxPolicy: validatetrans count"""
        self.assertEqual(self.p.validatetrans_count, 5)

    def test_136_allowxperm_count(self):
        """SELinuxPolicy: allowxperm rount"""
        self.assertEqual(self.p.allowxperm_count, 179)

    def test_137_allowxperm_count(self):
        """SELinuxPolicy: auditallowxperm rount"""
        self.assertEqual(self.p.auditallowxperm_count, 181)

    def test_138_neverallowxperm_count(self):
        """SELinuxPolicy: neverallowxperm rount"""
        self.assertEqual(self.p.neverallowxperm_count, 191)

    def test_139_allowxperm_count(self):
        """SELinuxPolicy: dontauditxperm rount"""
        self.assertEqual(self.p.dontauditxperm_count, 193)


class SELinuxPolicyLoadError(unittest.TestCase):

    """Test attempted loading of non-compiling policies."""

    def _load_policy(self, policy):
        self.assertRaises(InvalidPolicy, SELinuxPolicy, "tests/policyrep/invalid_policies/"+policy)

    def test_nodecon_invalid_range(self):
        """SELinuxPolicy: invalid nodecon range (category not associated) error."""
        self._load_policy("nodecon-invalid-range.conf")
        sys.stderr.write("The \"category can not be associated\" error above is expected.")

    # this is not fixed yet. See issue #72
    @unittest.expectedFailure
    def test_user_level_not_in_range(self):
        """SELinuxPolicy: error for user's default level isn't within the range."""
        self._load_policy("user-level-not-in-range.conf")
