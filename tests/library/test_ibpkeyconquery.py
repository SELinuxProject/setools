# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/ibpkeyconquery.conf")
class TestIbpkeyconQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with no criteria"""
        # query with no parameters gets all ibpkeycons.
        ibpkeycons = sorted(compiled_policy.ibpkeycons())

        q = setools.IbpkeyconQuery(compiled_policy)
        q_ibpkeycons = sorted(q.results())

        assert ibpkeycons == q_ibpkeycons

    def test_subnet_mask(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibpkeycon query with subnet mask match."""
        q = setools.IbpkeyconQuery(compiled_policy, subnet_prefix="fe81::")

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(1, 1)] == ibpkeycons

    def test_pkey_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibpkeycon query with exact pkey match."""
        q = setools.IbpkeyconQuery(compiled_policy, pkeys=(0x10c, 0x10e))

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(0x10c, 0x10e)] == ibpkeycons

    def test_user_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context user exact match"""
        q = setools.IbpkeyconQuery(compiled_policy, user="user20", user_regex=False)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(20, 20)] == ibpkeycons

    def test_user_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context user regex match"""
        q = setools.IbpkeyconQuery(compiled_policy, user="user21(a|b)", user_regex=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(0x21a, 0x21a),
                setools.IbpkeyconRange(0x21b, 0x21b)] == ibpkeycons

    def test_role_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context role exact match"""
        q = setools.IbpkeyconQuery(compiled_policy, role="role30_r", role_regex=False)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(30, 30)] == ibpkeycons

    def test_role_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context role regex match"""
        q = setools.IbpkeyconQuery(compiled_policy, role="role31(a|c)_r", role_regex=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(0x31a, 0x31a),
                setools.IbpkeyconRange(0x31c, 0x31c)] == ibpkeycons

    def test_type_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context type exact match"""
        q = setools.IbpkeyconQuery(compiled_policy, type_="type40", type_regex=False)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(40, 40)] == ibpkeycons

    def test_type_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context type regex match"""
        q = setools.IbpkeyconQuery(compiled_policy, type_="type41(b|c)", type_regex=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(0x41b, 0x41b),
                setools.IbpkeyconRange(0x41c, 0x41c)] == ibpkeycons

    def test_range_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range exact match"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s0:c1 - s0:c0.c4")

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(50, 50)] == ibpkeycons

    def test_range_overlap1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range overlap match (equal)"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(51, 51)] == ibpkeycons

    def test_range_overlap2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range overlap match (subset)"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c3",
                                   range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(51, 51)] == ibpkeycons

    def test_range_overlap3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range overlap match (superset)"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s1 - s1:c0.c4", range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(51, 51)] == ibpkeycons

    def test_range_overlap4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range overlap match (overlap low level)"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s1 - s1:c1,c2", range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(51, 51)] == ibpkeycons

    def test_range_overlap5(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range overlap match (overlap high level)"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c4",
                                   range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(51, 51)] == ibpkeycons

    def test_range_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range subset match"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s2:c1,c2 - s2:c0.c3",
                                   range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(52, 52)] == ibpkeycons

    def test_range_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range subset match (equal)"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(52, 52)] == ibpkeycons

    def test_range_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range superset match"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s3 - s3:c0.c4", range_superset=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(53, 53)] == ibpkeycons

    def test_range_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range superset match (equal)"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s3:c1 - s3:c1.c3", range_superset=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(53, 53)] == ibpkeycons

    def test_range_proper_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range proper subset match"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s4:c1,c2", range_subset=True,
                                   range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(54, 54)] == ibpkeycons

    def test_range_proper_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range proper subset match (equal)"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s4:c1 - s4:c1.c3", range_subset=True,
                                   range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [] == ibpkeycons

    def test_range_proper_subset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range proper subset match (equal low only)"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s4:c1 - s4:c1.c2", range_subset=True,
                                   range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(54, 54)] == ibpkeycons

    def test_range_proper_subset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range proper subset match (equal high only)"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s4:c1,c2 - s4:c1.c3",
                                   range_subset=True, range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(54, 54)] == ibpkeycons

    def test_range_proper_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range proper superset match"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s5 - s5:c0.c4", range_superset=True,
                                   range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(55, 55)] == ibpkeycons

    def test_range_proper_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range proper superset match (equal)"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s5:c1 - s5:c1.c3", range_superset=True,
                                   range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [] == ibpkeycons

    def test_range_proper_superset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range proper superset match (equal low)"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s5:c1 - s5:c1.c4", range_superset=True,
                                   range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(55, 55)] == ibpkeycons

    def test_range_proper_superset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ibpkeycon query with context range proper superset match (equal high)"""
        q = setools.IbpkeyconQuery(compiled_policy, range_="s5 - s5:c1.c3", range_superset=True,
                                   range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        assert [setools.IbpkeyconRange(55, 55)] == ibpkeycons

    def test_invalid_subnet_prefix(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibpkeycon query with invalid subnet prefix"""
        with pytest.raises(ValueError):
            setools.IbpkeyconQuery(compiled_policy, subnet_prefix="INVALID")

    def test_invalid_pkey_negative(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibpkeycon query with negative pkey"""
        with pytest.raises(ValueError):
            setools.IbpkeyconQuery(compiled_policy, pkeys=(-1, -1))

        with pytest.raises(ValueError):
            setools.IbpkeyconQuery(compiled_policy, pkeys=(1, -1))

        with pytest.raises(ValueError):
            setools.IbpkeyconQuery(compiled_policy, pkeys=(-1, 1))

    def test_invalid_pkey_zero(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibpkeycon query with 0 pkey"""
        with pytest.raises(ValueError):
            setools.IbpkeyconQuery(compiled_policy, pkeys=(0, 0))

    def test_invalid_pkey_over_max(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibpkeycon query with pkey over maximum value"""
        with pytest.raises(ValueError):
            setools.IbpkeyconQuery(compiled_policy, pkeys=(1, 0xfffff))

        with pytest.raises(ValueError):
            setools.IbpkeyconQuery(compiled_policy, pkeys=(0xfffff, 1))

        with pytest.raises(ValueError):
            setools.IbpkeyconQuery(compiled_policy, pkeys=(0xfffff, 0xfffff))

    def test_invalid_pkey_not_a_number(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibpkeycon query with pkey is not a number"""
        with pytest.raises(TypeError):
            setools.IbpkeyconQuery(compiled_policy, pkeys=(1, "INVALID"))

        with pytest.raises(TypeError):
            setools.IbpkeyconQuery(compiled_policy, pkeys=("INVALID", 2))

    def test_invalid_pkey_not_tuple(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibpkeycon query with pkey is not a tuple"""
        with pytest.raises(TypeError):
            setools.IbpkeyconQuery(compiled_policy, pkeys=1)

    def test_invalid_pkey_wrong_tuple_length(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibpkeycon query with pkey is not correct tuple size"""
        with pytest.raises(TypeError):
            setools.IbpkeyconQuery(compiled_policy, pkeys=(1,))

        with pytest.raises(TypeError):
            setools.IbpkeyconQuery(compiled_policy, pkeys=(1, 2, 3))
