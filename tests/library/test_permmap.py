# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
from unittest.mock import Mock

import pytest
import setools
from setools import PermissionMap, TERuletype
from setools.exception import PermissionMapParseError, RuleTypeError, \
    UnmappedClass, UnmappedPermission


@pytest.mark.obj_args("tests/library/permmap.conf")
class TestPermissionMap:

    """Permission map unit tests."""

    def validate_permmap_entry(self, permmap: dict, cls: str, perm: str, direction: str,
                               weight: int, enabled: bool) -> None:
        """Validate a permission map entry and settings."""
        assert cls in permmap
        assert perm in permmap[cls]
        assert 'direction' in permmap[cls][perm]
        assert 'weight' in permmap[cls][perm]
        assert 'enabled' in permmap[cls][perm]
        assert permmap[cls][perm]['direction'] == direction
        assert permmap[cls][perm]['weight'] == weight
        assert permmap[cls][perm]['enabled'] == enabled

    def test_load(self) -> None:
        """PermMap open from path."""
        permmap = PermissionMap("tests/library/perm_map")

        # validate permission map contents
        assert 5 == len(permmap._permmap)

        # class infoflow
        assert "infoflow" in permmap._permmap
        assert 6 == len(permmap._permmap['infoflow'])
        self.validate_permmap_entry(permmap._permmap, 'infoflow', 'low_w', 'w', 1, True)
        self.validate_permmap_entry(permmap._permmap, 'infoflow', 'med_w', 'w', 5, True)
        self.validate_permmap_entry(permmap._permmap, 'infoflow', 'hi_w', 'w', 10, True)
        self.validate_permmap_entry(permmap._permmap, 'infoflow', 'low_r', 'r', 1, True)
        self.validate_permmap_entry(permmap._permmap, 'infoflow', 'med_r', 'r', 5, True)
        self.validate_permmap_entry(permmap._permmap, 'infoflow', 'hi_r', 'r', 10, True)

        # class infoflow2
        assert "infoflow2" in permmap._permmap
        assert 7 == len(permmap._permmap['infoflow2'])
        self.validate_permmap_entry(permmap._permmap, 'infoflow2', 'low_w', 'w', 1, True)
        self.validate_permmap_entry(permmap._permmap, 'infoflow2', 'med_w', 'w', 5, True)
        self.validate_permmap_entry(permmap._permmap, 'infoflow2', 'hi_w', 'w', 10, True)
        self.validate_permmap_entry(permmap._permmap, 'infoflow2', 'low_r', 'r', 1, True)
        self.validate_permmap_entry(permmap._permmap, 'infoflow2', 'med_r', 'r', 5, True)
        self.validate_permmap_entry(permmap._permmap, 'infoflow2', 'hi_r', 'r', 10, True)
        self.validate_permmap_entry(permmap._permmap, 'infoflow2', 'super', 'b', 10, True)

        # class infoflow3
        assert "infoflow3" in permmap._permmap
        assert 1 == len(permmap._permmap['infoflow3'])
        self.validate_permmap_entry(permmap._permmap, 'infoflow3', 'null', 'n', 1, True)

        # class file
        assert "file" in permmap._permmap
        assert 2 == len(permmap._permmap['file'])
        self.validate_permmap_entry(permmap._permmap, 'file', 'execute', 'r', 10, True)
        self.validate_permmap_entry(permmap._permmap, 'file', 'entrypoint', 'r', 10, True)

        # class process
        assert "process" in permmap._permmap
        assert 1 == len(permmap._permmap['process'])
        self.validate_permmap_entry(permmap._permmap, 'process', 'transition', 'w', 10, True)

    def test_load_invalid(self) -> None:
        """PermMap load completely wrong file type"""
        with pytest.raises(PermissionMapParseError):
            PermissionMap("setup.py")

    def test_load_negative_class_count(self) -> None:
        """PermMap load negative class count"""
        with pytest.raises(PermissionMapParseError):
            PermissionMap("tests/library/invalid_perm_maps/negative-classcount")

    def test_load_non_number_class_count(self) -> None:
        """PermMap load non-number class count"""
        with pytest.raises(PermissionMapParseError):
            PermissionMap("tests/library/invalid_perm_maps/non-number-classcount")

    def test_load_extra_class(self) -> None:
        """PermMap load extra class"""
        with pytest.raises(PermissionMapParseError):
            PermissionMap("tests/library/invalid_perm_maps/extra-class")

    def test_load_bad_class_keyword(self) -> None:
        """PermMap load bad class keyword"""
        with pytest.raises(PermissionMapParseError):
            PermissionMap("tests/library/invalid_perm_maps/bad-class-keyword")

    # test 6: bad class name(?)

    def test_load_negative_perm_count(self) -> None:
        """PermMap load negative permission count"""
        with pytest.raises(PermissionMapParseError):
            PermissionMap("tests/library/invalid_perm_maps/negative-permcount")

    def test_load_bad_perm_count(self) -> None:
        """PermMap load bad permission count"""
        with pytest.raises(PermissionMapParseError):
            PermissionMap("tests/library/invalid_perm_maps/bad-permcount")

    # test 9: bad perm name(?)

    def test_load_extra_perms(self) -> None:
        """PermMap load negative permission count"""
        with pytest.raises(PermissionMapParseError):
            PermissionMap("tests/library/invalid_perm_maps/extra-perms")

    def test_load_invalid_flow_direction(self) -> None:
        """PermMap load invalid flow direction"""
        with pytest.raises(PermissionMapParseError):
            PermissionMap("tests/library/invalid_perm_maps/invalid-flowdir")

    def test_load_bad_perm_weight(self) -> None:
        """PermMap load too high/low permission weight"""
        with pytest.raises(PermissionMapParseError):
            PermissionMap("tests/library/invalid_perm_maps/bad-perm-weight-high")

        with pytest.raises(PermissionMapParseError):
            PermissionMap("tests/library/invalid_perm_maps/bad-perm-weight-low")

    def test_load_invalid_weight(self) -> None:
        """PermMap load invalid permission weight"""
        with pytest.raises(PermissionMapParseError):
            PermissionMap("tests/library/invalid_perm_maps/invalid-perm-weight")

    def test_set_weight(self) -> None:
        """PermMap set weight"""
        permmap = PermissionMap("tests/library/perm_map")
        self.validate_permmap_entry(permmap._permmap, 'infoflow2', 'low_w', 'w', 1, True)
        permmap.set_weight("infoflow2", "low_w", 10)
        self.validate_permmap_entry(permmap._permmap, 'infoflow2', 'low_w', 'w', 10, True)

    def test_set_weight_low(self) -> None:
        """PermMap set weight low"""
        permmap = PermissionMap("tests/library/perm_map")
        with pytest.raises(ValueError):
            permmap.set_weight("infoflow2", "low_w", 0)

        with pytest.raises(ValueError):
            permmap.set_weight("infoflow2", "low_w", -10)

    def test_set_weight_high(self) -> None:
        """PermMap set weight high"""
        permmap = PermissionMap("tests/library/perm_map")
        with pytest.raises(ValueError):
            permmap.set_weight("infoflow2", "low_w", 11)

        with pytest.raises(ValueError):
            permmap.set_weight("infoflow2", "low_w", 50)

    def test_set_weight_unmapped_class(self) -> None:
        """PermMap set weight unmapped class"""
        permmap = PermissionMap("tests/library/perm_map")
        with pytest.raises(UnmappedClass):
            permmap.set_weight("UNMAPPED", "write", 10)

    def test_set_weight_unmapped_permission(self) -> None:
        """PermMap set weight unmapped class"""
        permmap = PermissionMap("tests/library/perm_map")
        with pytest.raises(UnmappedPermission):
            permmap.set_weight("infoflow2", "UNMAPPED", 10)

    def test_set_direction(self) -> None:
        """PermMap set direction"""
        permmap = PermissionMap("tests/library/perm_map")
        self.validate_permmap_entry(permmap._permmap, 'infoflow2', 'low_w', 'w', 1, True)
        permmap.set_direction("infoflow2", "low_w", "r")
        self.validate_permmap_entry(permmap._permmap, 'infoflow2', 'low_w', 'r', 1, True)

    def test_set_direction_invalid(self) -> None:
        """PermMap set invalid direction"""
        permmap = PermissionMap("tests/library/perm_map")
        with pytest.raises(ValueError):
            permmap.set_direction("infoflow2", "low_w", "X")

    def test_set_direction_unmapped_class(self) -> None:
        """PermMap set direction unmapped class"""
        permmap = PermissionMap("tests/library/perm_map")
        with pytest.raises(UnmappedClass):
            permmap.set_direction("UNMAPPED", "write", "w")

    def test_set_direction_unmapped_permission(self) -> None:
        """PermMap set direction unmapped class"""
        permmap = PermissionMap("tests/library/perm_map")
        with pytest.raises(UnmappedPermission):
            permmap.set_direction("infoflow2", "UNMAPPED", "w")

    def test_exclude_perm(self) -> None:
        """PermMap exclude permission."""
        permmap = PermissionMap("tests/library/perm_map")
        permmap.exclude_permission("infoflow", "med_w")
        self.validate_permmap_entry(permmap._permmap, 'infoflow', 'med_w', 'w', 5, False)

    def test_exclude_perm_unmapped_class(self) -> None:
        """PermMap exclude permission unmapped class."""
        permmap = PermissionMap("tests/library/perm_map")
        with pytest.raises(UnmappedClass):
            permmap.exclude_permission("UNMAPPED", "med_w")

    def test_exclude_perm_unmapped_perm(self) -> None:
        """PermMap exclude permission unmapped permission."""
        permmap = PermissionMap("tests/library/perm_map")
        with pytest.raises(UnmappedPermission):
            permmap.exclude_permission("infoflow", "UNMAPPED")

    def test_include_perm(self) -> None:
        """PermMap include permission."""
        permmap = PermissionMap("tests/library/perm_map")
        permmap.exclude_permission("infoflow", "med_w")
        self.validate_permmap_entry(permmap._permmap, 'infoflow', 'med_w', 'w', 5, False)

        permmap.include_permission("infoflow", "med_w")
        self.validate_permmap_entry(permmap._permmap, 'infoflow', 'med_w', 'w', 5, True)

    def test_include_perm_unmapped_class(self) -> None:
        """PermMap include permission unmapped class."""
        permmap = PermissionMap("tests/library/perm_map")
        with pytest.raises(UnmappedClass):
            permmap.include_permission("UNMAPPED", "med_w")

    def test_include_perm_unmapped_perm(self) -> None:
        """PermMap include permission unmapped permission."""
        permmap = PermissionMap("tests/library/perm_map")
        with pytest.raises(UnmappedPermission):
            permmap.include_permission("infoflow", "UNMAPPED")

    def test_exclude_class(self) -> None:
        """PermMap exclude class."""
        permmap = PermissionMap("tests/library/perm_map")
        permmap.exclude_class("file")
        self.validate_permmap_entry(permmap._permmap, 'file', 'execute', 'r', 10, False)
        self.validate_permmap_entry(permmap._permmap, 'file', 'entrypoint', 'r', 10, False)

    def test_exclude_class_unmapped_class(self) -> None:
        """PermMap exclude class unmapped class."""
        permmap = PermissionMap("tests/library/perm_map")
        with pytest.raises(UnmappedClass):
            permmap.exclude_class("UNMAPPED")

    def test_include_class(self) -> None:
        """PermMap exclude class."""
        permmap = PermissionMap("tests/library/perm_map")
        permmap.exclude_class("file")
        self.validate_permmap_entry(permmap._permmap, 'file', 'execute', 'r', 10, False)
        self.validate_permmap_entry(permmap._permmap, 'file', 'entrypoint', 'r', 10, False)

        permmap.include_class("file")
        self.validate_permmap_entry(permmap._permmap, 'file', 'execute', 'r', 10, True)
        self.validate_permmap_entry(permmap._permmap, 'file', 'entrypoint', 'r', 10, True)

    def test_include_class_unmapped_class(self) -> None:
        """PermMap include class unmapped class."""
        permmap = PermissionMap("tests/library/perm_map")
        with pytest.raises(UnmappedClass):
            permmap.include_class("UNMAPPED")

    def test_weight_read_only(self) -> None:
        """PermMap get weight of read-only rule."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow"
        rule.perms = set(["med_r", "hi_r"])

        permmap = PermissionMap("tests/library/perm_map")
        weight = permmap.rule_weight(rule)
        assert weight.read == 10
        assert weight.write == 0

    def test_weight_write_only(self) -> None:
        """PermMap get weight of write-only rule."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow"
        rule.perms = set(["low_w", "med_w"])

        permmap = PermissionMap("tests/library/perm_map")
        weight = permmap.rule_weight(rule)
        assert weight.read == 0
        assert weight.write == 5

    def test_weight_both(self) -> None:
        """PermMap get weight of both rule."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow"
        rule.perms = set(["low_r", "hi_w"])

        permmap = PermissionMap("tests/library/perm_map")
        weight = permmap.rule_weight(rule)
        assert weight.read == 1
        assert weight.write == 10

    def test_weight_none(self) -> None:
        """PermMap get weight of none rule."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow3"
        rule.perms = set(["null"])

        permmap = PermissionMap("tests/library/perm_map")
        weight = permmap.rule_weight(rule)
        assert weight.read == 0
        assert weight.write == 0

    def test_weight_unmapped_class(self) -> None:
        """PermMap get weight of rule with unmapped class."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "unmapped"
        rule.perms = set(["null"])

        permmap = PermissionMap("tests/library/perm_map")
        pytest.raises(UnmappedClass, permmap.rule_weight, rule)

    def test_weight_unmapped_permission(self) -> None:
        """PermMap get weight of rule with unmapped permission."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow"
        rule.perms = set(["low_r", "unmapped"])

        permmap = PermissionMap("tests/library/perm_map")
        pytest.raises(UnmappedPermission, permmap.rule_weight, rule)

    def test_weight_wrong_rule_type(self) -> None:
        """PermMap get weight of rule with wrong rule type."""
        rule = Mock()
        rule.ruletype = TERuletype.type_transition
        rule.tclass = "infoflow"

        permmap = PermissionMap("tests/library/perm_map")
        pytest.raises(RuleTypeError, permmap.rule_weight, rule)

    def test_weight_excluded_permission(self) -> None:
        """PermMap get weight of a rule with excluded permission."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow"
        rule.perms = set(["med_r", "hi_r"])

        permmap = PermissionMap("tests/library/perm_map")
        permmap.exclude_permission("infoflow", "hi_r")
        weight = permmap.rule_weight(rule)
        assert weight.read == 5
        assert weight.write == 0

    def test_weight_excluded_class(self) -> None:
        """PermMap get weight of a rule with excluded class."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow"
        rule.perms = set(["low_r", "med_r", "hi_r", "low_w", "med_w", "hi_w"])

        permmap = PermissionMap("tests/library/perm_map")
        permmap.exclude_class("infoflow")
        weight = permmap.rule_weight(rule)
        assert weight.read == 0
        assert weight.write == 0

    def test_map_policy(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """PermMap create mappings for classes/perms in a policy."""
        permmap = PermissionMap("tests/library/perm_map")
        permmap.map_policy(compiled_policy)

        self.validate_permmap_entry(permmap._permmap, 'infoflow2', 'new_perm', 'u', 1, True)

        assert "new_class" in permmap._permmap
        assert 1 == len(permmap._permmap['new_class'])
        self.validate_permmap_entry(permmap._permmap, 'new_class', 'new_class_perm', 'u', 1, True)
