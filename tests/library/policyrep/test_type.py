# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/policyrep/type.conf")
class TestType:

    def test_string(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type basic string rendering."""
        type_ = compiled_policy.lookup_type("name10")
        assert "name10" == str(type_), f"{type_}"

    def test_attrs(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type with type attributes"""
        type_ = compiled_policy.lookup_type("name20")
        assert ["attr1", "attr2", "attr3"] == sorted(type_.attributes()), type_.attributes()

    def test_aliases(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type aliases"""
        type_ = compiled_policy.lookup_type("name30")
        assert ["alias1", "alias2", "alias3"] == sorted(type_.aliases()), type_.aliases()

    def test_expand(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type expansion"""
        type_ = compiled_policy.lookup_type("name40")
        expanded = list(type_.expand())
        assert 1 == len(expanded), len(expanded)
        assert expanded[0] is type_

    def test_permissive(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type is permissive"""
        type_ = compiled_policy.lookup_type("name50a")
        permtype = compiled_policy.lookup_type("name50b")
        assert not type_.ispermissive
        assert permtype.ispermissive

    def test_statement(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type basic statement"""
        type_ = compiled_policy.lookup_type("name60")
        assert "type name60;" == type_.statement(), type_.statement()

    def test_statement_one_attr(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type statement, one attribute"""
        type_ = compiled_policy.lookup_type("name61")
        assert "type name61, attr1;" == type_.statement(), type_.statement()

    def test_statement_two_attr(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type statement, two attributes"""
        type_ = compiled_policy.lookup_type("name62")
        assert "type name62, attr1, attr2;" == type_.statement(), type_.statement()

    def test_statement_one_alias(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type statement, one alias"""
        type_ = compiled_policy.lookup_type("name63")
        assert "type name63 alias alias4;" == type_.statement(), type_.statement()

    def test_statement_two_alias(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type statement, two aliases"""
        type_ = compiled_policy.lookup_type("name64")
        assert "type name64 alias { alias5 alias6 };" == type_.statement(), type_.statement()

    def test_statement_one_attr_one_alias(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type statement, one attribute, one alias"""
        type_ = compiled_policy.lookup_type("name65")
        assert "type name65 alias alias7, attr1;" == type_.statement(), type_.statement()

    def test_statement_two_attr_one_alias(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type statement, two attributes, one alias"""
        type_ = compiled_policy.lookup_type("name66")
        assert "type name66 alias alias8, attr2, attr3;" == type_.statement(), type_.statement()

    def test_statement_one_attr_two_alias(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type statement, one attribute, two aliases"""
        type_ = compiled_policy.lookup_type("name67")
        assert "type name67 alias { alias10 alias11 }, attr3;" == type_.statement(), \
            type_.statement()

    def test_statement_two_attr_two_alias(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type statement, two attributes, two aliases"""
        type_ = compiled_policy.lookup_type("name68")
        assert "type name68 alias { alias12 alias13 }, attr1, attr3;" == type_.statement(), \
            type_.statement()
