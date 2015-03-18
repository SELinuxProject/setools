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
import unittest

try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock

from setools import SELinuxPolicy
from setools.permmap import PermissionMap, UnmappedClass, UnmappedPermission, RuleTypeError


class PermissionMapTest(unittest.TestCase):

    def test_001_load(self):
        """PermMap open from path."""
        permmap = PermissionMap("tests/perm_map")

        # validate permission map contents
        self.assertEqual(5, len(permmap.permmap))

        # class infoflow
        self.assertIn("infoflow", permmap.permmap)
        self.assertEqual(6, len(permmap.permmap['infoflow']))
        self.assertIn("low_w", permmap.permmap['infoflow'])
        self.assertEqual(permmap.permmap['infoflow']['low_w']['direction'], 'w')
        self.assertEqual(permmap.permmap['infoflow']['low_w']['weight'], 1)
        self.assertTrue(permmap.permmap['infoflow']['low_w']['enabled'])

        self.assertIn("med_w", permmap.permmap['infoflow'])
        self.assertEqual(permmap.permmap['infoflow']['med_w']['direction'], 'w')
        self.assertEqual(permmap.permmap['infoflow']['med_w']['weight'], 5)
        self.assertTrue(permmap.permmap['infoflow']['med_w']['enabled'])

        self.assertIn("hi_w", permmap.permmap['infoflow'])
        self.assertEqual(permmap.permmap['infoflow']['hi_w']['direction'], 'w')
        self.assertEqual(permmap.permmap['infoflow']['hi_w']['weight'], 10)
        self.assertTrue(permmap.permmap['infoflow']['hi_w']['enabled'])

        self.assertIn("low_r", permmap.permmap['infoflow'])
        self.assertEqual(permmap.permmap['infoflow']['low_r']['direction'], 'r')
        self.assertEqual(permmap.permmap['infoflow']['low_r']['weight'], 1)
        self.assertTrue(permmap.permmap['infoflow']['low_r']['enabled'])

        self.assertIn("med_r", permmap.permmap['infoflow'])
        self.assertEqual(permmap.permmap['infoflow']['med_r']['direction'], 'r')
        self.assertEqual(permmap.permmap['infoflow']['med_r']['weight'], 5)
        self.assertTrue(permmap.permmap['infoflow']['med_r']['enabled'])

        self.assertIn("hi_r", permmap.permmap['infoflow'])
        self.assertEqual(permmap.permmap['infoflow']['hi_r']['direction'], 'r')
        self.assertEqual(permmap.permmap['infoflow']['hi_r']['weight'], 10)
        self.assertTrue(permmap.permmap['infoflow']['hi_r']['enabled'])

        # class infoflow2
        self.assertIn("infoflow2", permmap.permmap)
        self.assertEqual(7, len(permmap.permmap['infoflow2']))
        self.assertIn("low_w", permmap.permmap['infoflow2'])
        self.assertEqual(permmap.permmap['infoflow2']['low_w']['direction'], 'w')
        self.assertEqual(permmap.permmap['infoflow2']['low_w']['weight'], 1)
        self.assertTrue(permmap.permmap['infoflow2']['low_w']['enabled'])

        self.assertIn("med_w", permmap.permmap['infoflow2'])
        self.assertEqual(permmap.permmap['infoflow2']['med_w']['direction'], 'w')
        self.assertEqual(permmap.permmap['infoflow2']['med_w']['weight'], 5)
        self.assertTrue(permmap.permmap['infoflow2']['med_w']['enabled'])

        self.assertIn("hi_w", permmap.permmap['infoflow2'])
        self.assertEqual(permmap.permmap['infoflow2']['hi_w']['direction'], 'w')
        self.assertEqual(permmap.permmap['infoflow2']['hi_w']['weight'], 10)
        self.assertTrue(permmap.permmap['infoflow2']['hi_w']['enabled'])

        self.assertIn("low_r", permmap.permmap['infoflow2'])
        self.assertEqual(permmap.permmap['infoflow2']['low_r']['direction'], 'r')
        self.assertEqual(permmap.permmap['infoflow2']['low_r']['weight'], 1)
        self.assertTrue(permmap.permmap['infoflow2']['low_r']['enabled'])

        self.assertIn("med_r", permmap.permmap['infoflow2'])
        self.assertEqual(permmap.permmap['infoflow2']['med_r']['direction'], 'r')
        self.assertEqual(permmap.permmap['infoflow2']['med_r']['weight'], 5)
        self.assertTrue(permmap.permmap['infoflow2']['med_r']['enabled'])

        self.assertIn("hi_r", permmap.permmap['infoflow2'])
        self.assertEqual(permmap.permmap['infoflow2']['hi_r']['direction'], 'r')
        self.assertEqual(permmap.permmap['infoflow2']['hi_r']['weight'], 10)
        self.assertTrue(permmap.permmap['infoflow2']['hi_r']['enabled'])

        self.assertIn("super", permmap.permmap['infoflow2'])
        self.assertEqual(permmap.permmap['infoflow2']['super']['direction'], 'b')
        self.assertEqual(permmap.permmap['infoflow2']['super']['weight'], 10)
        self.assertTrue(permmap.permmap['infoflow2']['super']['enabled'])

        # class infoflow3
        self.assertIn("infoflow3", permmap.permmap)
        self.assertEqual(1, len(permmap.permmap['infoflow3']))
        self.assertIn("null", permmap.permmap['infoflow3'])
        self.assertEqual(permmap.permmap['infoflow3']['null']['direction'], 'n')
        self.assertEqual(permmap.permmap['infoflow3']['null']['weight'], 1)
        self.assertTrue(permmap.permmap['infoflow3']['null']['enabled'])

        # class file
        self.assertIn("file", permmap.permmap)
        self.assertEqual(2, len(permmap.permmap['file']))
        self.assertIn("execute", permmap.permmap['file'])
        self.assertEqual(permmap.permmap['file']['execute']['direction'], 'r')
        self.assertEqual(permmap.permmap['file']['execute']['weight'], 10)
        self.assertTrue(permmap.permmap['file']['execute']['enabled'])

        self.assertIn("entrypoint", permmap.permmap['file'])
        self.assertEqual(permmap.permmap['file']['entrypoint']['direction'], 'r')
        self.assertEqual(permmap.permmap['file']['entrypoint']['weight'], 10)
        self.assertTrue(permmap.permmap['file']['entrypoint']['enabled'])

        # class process
        self.assertIn("process", permmap.permmap)
        self.assertEqual(1, len(permmap.permmap['process']))
        self.assertIn("transition", permmap.permmap['process'])
        self.assertEqual(permmap.permmap['process']['transition']['direction'], 'w')
        self.assertEqual(permmap.permmap['process']['transition']['weight'], 10)
        self.assertTrue(permmap.permmap['process']['transition']['enabled'])

    # 100 get/set weight
    # 110 get/set direction

    def test_120_exclude_perm(self):
        """PermMap exclude permission."""
        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_permission("infoflow", "med_w")
        self.assertFalse(permmap.permmap['infoflow']['med_w']['enabled'])

    def test_121_reinclude_perm(self):
        """PermMap include permission."""
        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_permission("infoflow", "med_w")
        self.assertFalse(permmap.permmap['infoflow']['med_w']['enabled'])

        permmap.include_permission("infoflow", "med_w")
        self.assertTrue(permmap.permmap['infoflow']['med_w']['enabled'])

    def test_122_exclude_class(self):
        """PermMap exclude class."""
        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_class("file")
        self.assertFalse(permmap.permmap['file']['execute']['enabled'])
        self.assertFalse(permmap.permmap['file']['entrypoint']['enabled'])

    def test_123_include_class(self):
        """PermMap exclude class."""
        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_class("file")
        self.assertFalse(permmap.permmap['file']['execute']['enabled'])
        self.assertFalse(permmap.permmap['file']['entrypoint']['enabled'])

        permmap.include_class("file")
        self.assertTrue(permmap.permmap['file']['execute']['enabled'])
        self.assertTrue(permmap.permmap['file']['entrypoint']['enabled'])

    def test_130_weight_read_only(self):
        """PermMap get weight of read-only rule."""
        rule = MagicMock()
        rule.ruletype = "allow"
        rule.tclass = "infoflow"
        rule.perms = set(["med_r", "hi_r"])

        permmap = PermissionMap("tests/perm_map")
        r, w = permmap.rule_weight(rule)
        self.assertEqual(r, 10)
        self.assertEqual(w, 0)

    def test_131_weight_write_only(self):
        """PermMap get weight of write-only rule."""
        rule = MagicMock()
        rule.ruletype = "allow"
        rule.tclass = "infoflow"
        rule.perms = set(["low_w", "med_w"])

        permmap = PermissionMap("tests/perm_map")
        r, w = permmap.rule_weight(rule)
        self.assertEqual(r, 0)
        self.assertEqual(w, 5)

    def test_132_weight_both(self):
        """PermMap get weight of both rule."""
        rule = MagicMock()
        rule.ruletype = "allow"
        rule.tclass = "infoflow"
        rule.perms = set(["low_r", "hi_w"])

        permmap = PermissionMap("tests/perm_map")
        r, w = permmap.rule_weight(rule)
        self.assertEqual(r, 1)
        self.assertEqual(w, 10)

    def test_133_weight_none(self):
        """PermMap get weight of none rule."""
        rule = MagicMock()
        rule.ruletype = "allow"
        rule.tclass = "infoflow3"
        rule.perms = set(["null"])

        permmap = PermissionMap("tests/perm_map")
        r, w = permmap.rule_weight(rule)
        self.assertEqual(r, 0)
        self.assertEqual(w, 0)

    def test_134_weight_unmapped_class(self):
        """PermMap get weight of rule with unmapped class."""
        rule = MagicMock()
        rule.ruletype = "allow"
        rule.tclass = "unmapped"
        rule.perms = set(["null"])

        permmap = PermissionMap("tests/perm_map")
        self.assertRaises(UnmappedClass, permmap.rule_weight, rule)

    def test_135_weight_unmapped_permission(self):
        """PermMap get weight of rule with unmapped permission."""
        rule = MagicMock()
        rule.ruletype = "allow"
        rule.tclass = "infoflow"
        rule.perms = set(["low_r", "unmapped"])

        permmap = PermissionMap("tests/perm_map")
        self.assertRaises(UnmappedPermission, permmap.rule_weight, rule)

    def test_136_weight_wrong_rule_type(self):
        """PermMap get weight of rule with wrong rule type."""
        rule = MagicMock()
        rule.ruletype = "type_transition"
        rule.tclass = "infoflow"

        permmap = PermissionMap("tests/perm_map")
        self.assertRaises(RuleTypeError, permmap.rule_weight, rule)

    def test_133_weight_excluded_permission(self):
        """PermMap get weight of a rule with excluded permission."""
        rule = MagicMock()
        rule.ruletype = "allow"
        rule.tclass = "infoflow"
        rule.perms = set(["med_r", "hi_r"])

        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_permission("infoflow", "hi_r")
        r, w = permmap.rule_weight(rule)
        self.assertEqual(r, 5)
        self.assertEqual(w, 0)

    def test_133_weight_excluded_class(self):
        """PermMap get weight of a rule with excluded class."""
        rule = MagicMock()
        rule.ruletype = "allow"
        rule.tclass = "infoflow"
        rule.perms = set(["low_r", "med_r", "hi_r", "low_w", "med_w", "hi_w"])

        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_class("infoflow")
        r, w = permmap.rule_weight(rule)
        self.assertEqual(r, 0)
        self.assertEqual(w, 0)

    def test_150_map_policy(self):
        """PermMap create mappings for classes/perms in a policy."""
        policy = SELinuxPolicy("tests/permmap.conf")
        permmap = PermissionMap("tests/perm_map")
        permmap.map_policy(policy)

        self.assertIn("new_perm", permmap.permmap['infoflow2'])
        self.assertEqual(permmap.permmap['infoflow2']['new_perm']['direction'], 'u')
        self.assertEqual(permmap.permmap['infoflow2']['new_perm']['weight'], 1)
        self.assertTrue(permmap.permmap['infoflow2']['new_perm']['enabled'])

        self.assertIn("new_class", permmap.permmap)
        self.assertIn("new_class_perm", permmap.permmap['new_class'])
        self.assertEqual(permmap.permmap['new_class']['new_class_perm']['direction'], 'u')
        self.assertEqual(permmap.permmap['new_class']['new_class_perm']['weight'], 1)
        self.assertTrue(permmap.permmap['new_class']['new_class_perm']['enabled'])
