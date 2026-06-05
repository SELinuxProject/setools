# SPDX-License-Identifier: GPL-2.0-only
#
# Each test class declares the policy file it needs via @pytest.mark.obj_args().
# The mcp_server fixture (see tests/conftest.py) reads that marker and instantiates
# SEToolsMCPServer with the given policy path.
#
# Xen-specific tools are tested in classes marked with the Xen policy.
#
# pylint: disable=invalid-name

import json

import pytest

from setools.mcp.server import SEToolsMCPServer

# Use existing test policies; no need to create new ones just for MCP server tests
SELINUX_POLICY = "tests/library/policyrep/selinuxpolicy.conf"
XEN_POLICY = "tests/library/policyrep/selinuxpolicy-xen.conf"
INFOFLOW_POLICY = "tests/library/infoflow.conf"
PERM_MAP = "tests/library/perm_map"
DTA_POLICY = "tests/library/dta.conf"
DIFF_LEFT_POLICY = "tests/library/diff_left.conf"
DIFF_RIGHT_POLICY = "tests/library/diff_right.conf"


@pytest.fixture(scope="class")
def mcp_server(compiled_policy) -> SEToolsMCPServer:
    """Return an SEToolsMCPServer loaded with the policy from @pytest.mark.obj_args."""
    return SEToolsMCPServer(compiled_policy.path)


@pytest.fixture(scope="class")
def mcp_server2(policy_pair: tuple) -> tuple[SEToolsMCPServer, str, str]:
    """Return an SEToolsMCPServer loaded with the two policies from @pytest.mark.obj_args."""
    left, right = policy_pair
    mcp = SEToolsMCPServer(left.path)
    mcp._load_policy(right.path)  # Preload the second policy so it's available for diffing
    return mcp, left.path, right.path


def assert_payload(payload: str) -> dict:
    """Assert that the payload is valid JSON and contains expected top level keys."""
    data = json.loads(payload)
    assert len(data) == 3, f"{data!r}"
    assert "result" in data, f"{data!r}"
    assert "truncated" in data, f"{data!r}"
    assert isinstance(data["truncated"], bool), f"{data!r}"
    assert "count" in data, f"{data!r}"
    assert isinstance(data["count"], int), f"{data!r}"
    assert data["count"] >= 0, f"{data!r}"
    return data


@pytest.mark.obj_args(SELINUX_POLICY)
class TestGetPolicyInfo:
    def test_returns_valid_json(self, mcp_server: SEToolsMCPServer) -> None:
        result = assert_payload(mcp_server.setools_get_policy_info())["result"]
        assert "version" in result
        assert "mls" in result
        assert "counts" in result

    def test_counts_are_positive(self, mcp_server: SEToolsMCPServer) -> None:
        counts = assert_payload(mcp_server.setools_get_policy_info())["result"]["counts"]
        assert counts["types"] > 0
        assert counts["allow_rules"] > 0


@pytest.mark.obj_args(XEN_POLICY, xen=True)
class TestGetPolicyInfoXen:
    def test_xen_policy(self, mcp_server: SEToolsMCPServer) -> None:
        result = assert_payload(mcp_server.setools_get_policy_info())["result"]
        assert result["target_platform"] == "xen"


@pytest.mark.obj_args(SELINUX_POLICY)
class TestSearchTERules:
    def test_unfiltered_returns_rules(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_search_te_rules(max_results=5))
        assert data["count"] > 0
        assert "result" in data

    def test_source_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_search_te_rules(ruletypes=["allow"],
                                                                 source="type30",
                                                                 source_indirect=False,
                                                                 max_results=10))
        for rule in data["result"]:
            assert rule["ruletype"] == "allow"
            assert rule["source"] == "type30"

    def test_tclass_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_search_te_rules(ruletypes=["allow"],
                                                                 tclass=["infoflow"],
                                                                 max_results=5))
        for rule in data["result"]:
            assert rule["tclass"] == "infoflow"

    def test_truncation(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_search_te_rules(max_results=2))
        assert data["count"] == 2
        assert data["truncated"] is True

    def test_no_results(self, mcp_server: SEToolsMCPServer) -> None:
        # Use a regex pattern that matches nothing
        data = assert_payload(mcp_server.setools_search_te_rules(source="^__nonexistent_type_z__$",
                                                                 source_regex=True))
        assert data["count"] == 0
        assert data["truncated"] is False

    def test_rule_dict_has_required_keys(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_search_te_rules(ruletypes=["allow"],
                                                                 max_results=1))
        rule = data["result"][0]
        for key in ("statement", "ruletype", "source", "target", "tclass"):
            assert key in rule


@pytest.mark.obj_args(SELINUX_POLICY)
class TestSearchRBACRules:
    def test_unfiltered_returns_rules(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_search_rbac_rules(max_results=5))
        assert data["count"] > 0

    def test_role_allow_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_search_rbac_rules(ruletypes=["allow"],
                                                                   max_results=5))
        for rule in data["result"]:
            assert rule["ruletype"] == "allow"

    def test_role_transition_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_search_rbac_rules(ruletypes=["role_transition"],
                                                                   max_results=5))
        for rule in data["result"]:
            assert rule["ruletype"] == "role_transition"

    def test_rule_dict_has_required_keys(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_search_rbac_rules(max_results=1))
        rule = data["result"][0]
        for key in ("statement", "ruletype", "source", "target"):
            assert key in rule


@pytest.mark.obj_args(SELINUX_POLICY)
class TestSearchMLSRules:
    def test_unfiltered_returns_rules(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_search_mls_rules(max_results=5))
        assert data["count"] > 0

    def test_range_transition_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_search_mls_rules(ruletypes=["range_transition"],
                                                                  max_results=5))
        for rule in data["result"]:
            assert rule["ruletype"] == "range_transition"

    def test_rule_dict_has_required_keys(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_search_mls_rules(max_results=1))
        rule = data["result"][0]
        for key in ("statement", "ruletype", "source", "target", "tclass", "default"):
            assert key in rule


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListTypes:
    def test_unfiltered(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_types(max_results=10))
        assert data["count"] > 0

    def test_name_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_types(name="type18"))
        assert data["count"] == 1
        assert data["result"][0]["name"] == "type18"

    def test_name_regex(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_types(name="type2.", name_regex=True,
                                                            max_results=20))
        for t in data["result"]:
            assert "type2" in t["name"]

    def test_type_dict_has_required_keys(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_types(max_results=1))
        t = data["result"][0]
        for key in ("name", "permissive", "attributes", "aliases"):
            assert key in t

    def test_permissive_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_types(permissive=True, max_results=10))
        # All returned types should be permissive
        for t in data["result"]:
            assert t["permissive"]


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListAttributes:
    def test_unfiltered_returns_attrs(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_type_attributes(max_results=10))
        assert data["count"] > 0

    def test_name_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_type_attributes(name="attr0"))
        assert data["count"] == 1
        assert data["result"][0]["name"] == "attr0"

    def test_attr_dict_has_required_keys(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_type_attributes(max_results=1))
        attr = data["result"][0]
        for key in ("name", "types"):
            assert key in attr

    def test_domain_attr_contains_type(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_type_attributes(name="attr0"))
        types = data["result"][0]["types"]
        assert "type1" in types


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListRoles:
    def test_unfiltered_returns_roles(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_roles(max_results=10))
        assert data["count"] > 0

    def test_object_r_present(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_roles(name="object_r"))
        assert data["count"] == 1

    def test_role_dict_has_required_keys(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_roles(max_results=1))
        role = data["result"][0]
        for key in ("name", "types"):
            assert key in role


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListRoleTypes:
    def test_types(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_role_types(type_name="type0"))
        assert data["count"] > 0

    def test_no_results_for_nonexistent_type(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_role_types(type_name="__nonexistent_xyz__"))
        assert data["count"] == 0


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListUsers:
    def test_unfiltered_returns_users(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_users(max_results=10))
        assert data["count"] > 0

    def test_name_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_users(name="user1"))
        assert data["count"] == 1

    def test_user_dict_has_required_keys(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_users(max_results=1))
        user = data["result"][0]
        for key in ("name", "roles"):
            assert key in user


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListClasses:
    def test_unfiltered_returns_classes(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_classes(max_results=20))
        assert data["count"] > 0

    def test_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_classes(name="infoflow7"))
        assert data["count"] == 1
        assert data["result"][0]["name"] == "infoflow7"


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListCommons:
    def test_unfiltered_returns_commons(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_commons(max_results=20))
        assert data["count"] > 0

    def test_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_commons(name="hi_c"))
        assert data["count"] == 1
        assert len(data["result"][0]["perms"]) > 0


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListBooleans:
    def test_unfiltered_returns_booleans(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_booleans(max_results=10))
        assert data["count"] > 0

    def test_state_true_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_booleans(state=True, max_results=10))
        for b in data["result"]:
            assert b["default_state"] is True

    def test_state_false_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_booleans(state=False, max_results=10))
        for b in data["result"]:
            assert b["default_state"] is False


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListSensitivities:
    def test_unfiltered(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_sensitivities(max_results=10))
        assert data["count"] > 0

    def test_name_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_sensitivities(name="s0"))
        assert data["count"] == 1
        assert data["result"][0]["name"] == "s0"


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListCategories:
    def test_unfiltered_returns_categories(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_categories(max_results=10))
        assert data["count"] > 0

    def test_filteer(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_categories(name="c0"))
        assert data["count"] == 1


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListPolcaps:
    def test_unfiltered_returns_polcaps(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_polcaps())
        assert data["count"] > 0

    def test_name_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_polcaps(name="open_perms"))
        assert data["count"] == 1


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListPermissiveTypes:
    def test_unfiltered(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_permissive_types())
        assert data["count"] > 0


# @pytest.mark.obj_args(SELINUX_POLICY)
# class TestListTypebounds:
#     def test_unfiltered(self, mcp_server: SEToolsMCPServer) -> None:
#         data = assert_payload(mcp_server.setools_list_typebounds())
#         assert data["count"] > 0
#         assert "typebounds" in data


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListConstraints:
    def test_unfiltered(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_constraints())
        assert data["count"] > 0

    def test_tclass_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_constraints(tclass=["infoflow"]))
        for c in data["result"]:
            assert c["tclass"] == "infoflow"

    def test_explicit_ruletypes(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_constraints(ruletypes=["constrain"]))
        for c in data["result"]:
            assert c["ruletype"] == "constrain"

    def test_constraint_dict_has_required_keys(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_constraints())
        c = data["result"][0]
        for key in ("statement", "ruletype", "tclass"):
            assert key in c

    def test_invalid_ruletype_raises(self, mcp_server: SEToolsMCPServer) -> None:
        with pytest.raises(ValueError):
            mcp_server.setools_list_constraints(ruletypes=["not_a_real_ruletype"])


# @pytest.mark.obj_args(SELINUX_POLICY)
# class TestListDefaults:
#     def test_unfiltered(self, mcp_server: SEToolsMCPServer) -> None:
#         data = assert_payload(mcp_server.setools_list_defaults())
#         assert data["count"] > 0

#     def test_ruletype_filter(self, mcp_server: SEToolsMCPServer) -> None:
#         data = assert_payload(mcp_server.setools_list_defaults(ruletypes=["default_role"]))
#         for d in data["defaults"]:
#             assert d["ruletype"] == "default_role"


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListFsUses:
    def test_unfiltered_returns_entries(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_fs_uses())
        assert data["count"] > 0

    def test_fs_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_fs_uses(fs="fs0"))
        assert data["count"] > 0
        for fsu in data["result"]:
            assert fsu["fs"] == "fs0"

    def test_ruletype_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_fs_uses(ruletypes=["fs_use_xattr"]))
        for fsu in data["result"]:
            assert fsu["ruletype"] == "fs_use_xattr"


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListGenfscons:
    def test_unfiltered_returns_entries(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_genfscons())
        assert data["count"] > 0

    def test_fs_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_genfscons(fs="fs149"))
        assert data["count"] > 0
        for g in data["result"]:
            assert g["fs"] == "fs149"

    def test_genfscon_dict_has_required_keys(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_genfscons(max_results=1))
        g = data["result"][0]
        for key in ("statement", "fs", "path", "context"):
            assert key in g


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListInitialsids:
    def test_unfiltered_returns_entries(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_initialsids())
        assert data["count"] > 0

    def test_name_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_initialsids(name="kernel"))
        assert data["count"] == 1
        assert data["result"][0]["name"] == "kernel"


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListPortcons:
    def test_unfiltered_returns_entries(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_portcons())
        assert data["count"] > 0

    def test_port_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_portcons(ports="80"))
        assert data["count"] > 0
        for pc in data["result"]:
            assert pc["ports_low"] <= 80 <= pc["ports_high"]

    def test_protocol_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_portcons(protocol="tcp", max_results=10))
        for pc in data["result"]:
            assert pc["protocol"] == "tcp"


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListNetifcons:
    def test_unfiltered_returns_entries(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_netifcons())
        assert data["count"] > 0

    def test_name_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data_filtered = assert_payload(mcp_server.setools_list_netifcons(name="eth0"))
        assert data_filtered["count"] >= 1


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListNodecons:
    def test_unfiltered_returns_entries(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_nodecons())
        assert data["count"] > 0

    def test_nodecon_dict_has_required_keys(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_nodecons(max_results=1))
        n = data["result"][0]
        for key in ("statement", "network", "ip_version", "context"):
            assert key in n

    def test_ipv4_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_nodecons(ip_version="ipv4", max_results=5))
        for n in data["result"]:
            assert n["ip_version"] == "ipv4"

    def test_network_filter(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_nodecons(network="0.0.0.0/0"))
        assert data["count"] > 0


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListIbpkeycons:
    def test_unfiltered(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_ibpkeycons())
        assert data["count"] > 0


@pytest.mark.obj_args(SELINUX_POLICY)
class TestListIbendportcons:
    def test_unfiltered(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_ibendportcons())
        assert data["count"] > 0


@pytest.mark.obj_args(XEN_POLICY, xen=True)
class TestListIomemcons:
    def test_unfiltered(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_iomemcons())
        assert data["count"] > 0


@pytest.mark.obj_args(XEN_POLICY, xen=True)
class TestListIoportcons:
    def test_unfiltered(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_ioportcons())
        assert data["count"] > 0


@pytest.mark.obj_args(XEN_POLICY, xen=True)
class TestListPcidevicecons:
    def test_unfiltered(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_pcidevicecons())
        assert data["count"] > 0


@pytest.mark.obj_args(XEN_POLICY, xen=True)
class TestListPirqcons:
    def test_unfiltered(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_pirqcons())
        assert data["count"] > 0


@pytest.mark.obj_args(XEN_POLICY, xen=True)
class TestListDevicetreecons:
    def test_unfiltered(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_list_devicetreecons())
        assert data["count"] > 0


@pytest.mark.obj_args(DTA_POLICY)
class TestAnalyzeDTA:
    def test_transitions_out(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_analyze_dta(mode="TransitionsOut", source="start",
                              max_results=5))
        assert data["count"] > 0

    def test_transitions_in(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_analyze_dta(mode="TransitionsIn", target="trans1",
                              max_results=5))
        assert data["count"] > 0

    def test_shortest_paths(self, mcp_server: SEToolsMCPServer) -> None:
        # Find a target that kernel_t can reach
        data = assert_payload(mcp_server.setools_analyze_dta(mode="ShortestPaths", source="trans2",
                              target="trans3", max_results=5))
        assert data["count"] > 0
        assert isinstance(data["result"][0]["path"], list)

    def test_invalid_mode_raises(self, mcp_server: SEToolsMCPServer) -> None:
        with pytest.raises(ValueError):
            mcp_server.setools_analyze_dta(mode="bad_mode")


@pytest.mark.obj_args(INFOFLOW_POLICY)
class TestAnalyzeInfoFlow:
    def test_flows_out(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_analyze_info_flow(mode="FlowsOut", source="node1",
                              perm_map_path=PERM_MAP, max_results=5))
        assert data["count"] > 0

    def test_flows_in(self, mcp_server: SEToolsMCPServer) -> None:
        data = assert_payload(mcp_server.setools_analyze_info_flow(mode="FlowsIn", target="node2",
                              perm_map_path=PERM_MAP, max_results=5))
        assert data["count"] > 0

    def test_shortest_paths(self, mcp_server: SEToolsMCPServer) -> None:
        # Find a target that kernel_t can flow to
        data = assert_payload(mcp_server.setools_analyze_info_flow(mode="ShortestPaths",
                              source="node1", target="node4", perm_map_path=PERM_MAP,
                              max_results=5))
        assert data["count"] > 0
        assert isinstance(data["result"][0]["path"], list)

    def test_invalid_mode_raises(self, mcp_server: SEToolsMCPServer) -> None:
        with pytest.raises(ValueError):
            mcp_server.setools_analyze_info_flow(mode="bad_mode")


@pytest.mark.obj_args(DIFF_LEFT_POLICY, DIFF_RIGHT_POLICY)
class TestDiffPolicies:
    def test_identical_policies(self, mcp_server2: tuple[SEToolsMCPServer, str, str]) -> None:
        server, left, _ = mcp_server2
        data = assert_payload(server.setools_diff_policies(
            left, left, components=["types"],))
        assert data["result"]["types"]["added"] == []
        assert data["result"]["types"]["removed"] == []
        assert data["count"] == 0
        assert data["truncated"] is False

    def test_diff(self, mcp_server2: tuple[SEToolsMCPServer, str, str]) -> None:
        # tests/library/mcp/diff_left.conf vs policy-full.33 differ in TE rules
        server, left, right = mcp_server2
        data = assert_payload(server.setools_diff_policies(
            left, right, components=["te_rules", "types"]))
        diffs = data["result"]
        # The two full policy files should differ in at least TE rules or types
        has_any_diff = (
            diffs["types"]["added"]
            or diffs["types"]["removed"]
            or diffs["te_rules"]["added_allows"]["rules"]
            or diffs["te_rules"]["removed_allows"]["rules"]
            or diffs["te_rules"]["modified_allows"]["rules"]
        )
        assert has_any_diff
        assert data["count"] > 0

    def test_invalid_component_raises(self,
                                      mcp_server2: tuple[SEToolsMCPServer, str, str]) -> None:
        server, left, right = mcp_server2
        with pytest.raises(ValueError):
            server.setools_diff_policies(left, right, components=["bad_component"])

    def test_te_rules_component_structure(self,
                                          mcp_server2: tuple[SEToolsMCPServer, str, str]) -> None:
        server, left, right = mcp_server2
        data = assert_payload(server.setools_diff_policies(
            left, right, components=["te_rules"]))
        te = data["result"]["te_rules"]
        for key in ("added_allows", "removed_allows", "modified_allows"):
            assert key in te

    def test_rbac_rules_component(self,
                                  mcp_server2: tuple[SEToolsMCPServer, str, str]) -> None:
        server, left, right = mcp_server2
        data = assert_payload(server.setools_diff_policies(
            left, right, components=["rbac_rules"]))
        rbac = data["result"]["rbac_rules"]
        for key in ("added_role_allows", "removed_role_allows",
                    "added_role_transitions", "removed_role_transitions"):
            assert key in rbac

    def test_mls_rules_component(self,
                                 mcp_server2: tuple[SEToolsMCPServer, str, str]) -> None:
        server, left, right = mcp_server2
        data = assert_payload(server.setools_diff_policies(
            left, right, components=["mls_rules"]))
        mls = data["result"]["mls_rules"]
        for key in ("added_range_transitions", "removed_range_transitions"):
            assert key in mls

    def test_portcons_component(self,
                                mcp_server2: tuple[SEToolsMCPServer, str, str]) -> None:
        server, left, right = mcp_server2
        data = assert_payload(server.setools_diff_policies(
            left, right, components=["portcons"]))
        pc = data["result"]["portcons"]
        for key in ("added", "removed"):
            assert key in pc
