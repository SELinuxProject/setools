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
from setools.permmap import PermissionMap
from setools.exception import RuleTypeError, UnmappedClass, UnmappedPermission


class PermissionMapTest(unittest.TestCase):

    """Permission map unit tests."""

    def validate_permmap_entry(self, permmap, cls, perm, direction, weight, enabled):
        """Validate a permission map entry and settings."""
        self.assertIn(cls, permmap)
        self.assertIn(perm, permmap[cls])
        self.assertIn('direction', permmap[cls][perm])
        self.assertIn('weight', permmap[cls][perm])
        self.assertIn('enabled', permmap[cls][perm])
        self.assertEqual(permmap[cls][perm]['direction'], direction)
        self.assertEqual(permmap[cls][perm]['weight'], weight)

        if enabled:
            self.assertTrue(permmap[cls][perm]['enabled'])
        else:
            self.assertFalse(permmap[cls][perm]['enabled'])

    def test_001_load(self):
        """PermMap open from path."""
        permmap = PermissionMap("tests/perm_map")

        # validate permission map contents
        self.assertEqual(5, len(permmap.permmap))

        # class infoflow
        self.assertIn("infoflow", permmap.permmap)
        self.assertEqual(6, len(permmap.permmap['infoflow']))
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'low_w', 'w', 1, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'med_w', 'w', 5, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'hi_w', 'w', 10, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'low_r', 'r', 1, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'med_r', 'r', 5, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'hi_r', 'r', 10, True)

        # class infoflow2
        self.assertIn("infoflow2", permmap.permmap)
        self.assertEqual(7, len(permmap.permmap['infoflow2']))
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'low_w', 'w', 1, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'med_w', 'w', 5, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'hi_w', 'w', 10, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'low_r', 'r', 1, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'med_r', 'r', 5, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'hi_r', 'r', 10, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'super', 'b', 10, True)

        # class infoflow3
        self.assertIn("infoflow3", permmap.permmap)
        self.assertEqual(1, len(permmap.permmap['infoflow3']))
        self.validate_permmap_entry(permmap.permmap, 'infoflow3', 'null', 'n', 1, True)

        # class file
        self.assertIn("file", permmap.permmap)
        self.assertEqual(2, len(permmap.permmap['file']))
        self.validate_permmap_entry(permmap.permmap, 'file', 'execute', 'r', 10, True)
        self.validate_permmap_entry(permmap.permmap, 'file', 'entrypoint', 'r', 10, True)

        # class process
        self.assertIn("process", permmap.permmap)
        self.assertEqual(1, len(permmap.permmap['process']))
        self.validate_permmap_entry(permmap.permmap, 'process', 'transition', 'w', 10, True)

    # 100 get/set weight
    # 110 get/set direction

    def test_120_exclude_perm(self):
        """PermMap exclude permission."""
        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_permission("infoflow", "med_w")
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'med_w', 'w', 5, False)

    def test_121_reinclude_perm(self):
        """PermMap include permission."""
        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_permission("infoflow", "med_w")
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'med_w', 'w', 5, False)

        permmap.include_permission("infoflow", "med_w")
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'med_w', 'w', 5, True)

    def test_122_exclude_class(self):
        """PermMap exclude class."""
        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_class("file")
        self.validate_permmap_entry(permmap.permmap, 'file', 'execute', 'r', 10, False)
        self.validate_permmap_entry(permmap.permmap, 'file', 'entrypoint', 'r', 10, False)

    def test_123_include_class(self):
        """PermMap exclude class."""
        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_class("file")
        self.validate_permmap_entry(permmap.permmap, 'file', 'execute', 'r', 10, False)
        self.validate_permmap_entry(permmap.permmap, 'file', 'entrypoint', 'r', 10, False)

        permmap.include_class("file")
        self.validate_permmap_entry(permmap.permmap, 'file', 'execute', 'r', 10, True)
        self.validate_permmap_entry(permmap.permmap, 'file', 'entrypoint', 'r', 10, True)

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

        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'new_perm', 'u', 1, True)

        self.assertIn("new_class", permmap.permmap)
        self.assertEqual(1, len(permmap.permmap['new_class']))
        self.validate_permmap_entry(permmap.permmap, 'new_class', 'new_class_perm', 'u', 1, True)
