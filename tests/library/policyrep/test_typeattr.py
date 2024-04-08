# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/policyrep/typeattr.conf")
class TestTypeAttribute:

    def test_string(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TypeAttribute basic string rendering."""
        attr = compiled_policy.lookup_typeattr("name10")
        assert "name10" == str(attr), f"{attr}"

    def test_attrs(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TypeAttribute attributes"""
        attr = compiled_policy.lookup_typeattr("name20")
        with pytest.raises(setools.exception.SymbolUseError):
            attr.attributes()

    def test_aliases(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TypeAttribute aliases"""
        attr = compiled_policy.lookup_typeattr("name30")
        with pytest.raises(setools.exception.SymbolUseError):
            attr.aliases()

    def test_expand(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TypeAttribute expansion"""
        attr = compiled_policy.lookup_typeattr("name40")
        assert ['type31a', 'type31b', 'type31c'] == sorted(attr.expand()), sorted(attr.expand())

    def test_permissive(self, compiled_policy: setools.SELinuxPolicy) -> None:
        attr = compiled_policy.lookup_typeattr("name50")
        with pytest.raises(setools.exception.SymbolUseError):
            attr.ispermissive

    def test_statement(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TypeAttribute basic statement"""
        attr = compiled_policy.lookup_typeattr("name60")
        assert "attribute name60;" == attr.statement(), attr.statement()

    def test_contains(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TypeAttribute: contains"""
        attr = compiled_policy.lookup_typeattr("name70")
        assert "type31b" in attr
        assert "type30" not in attr
