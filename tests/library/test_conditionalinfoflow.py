# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools

# Note: the testing for having correct rules on every edge is only
# performed once on the full graph, since it is assumed that NetworkX's
# Digraph.subgraph() function correctly copies the edge attributes into
# the subgraph.


@pytest.fixture
def analysis(compiled_policy: setools.SELinuxPolicy) -> setools.InfoFlowAnalysis:
    perm_map = setools.PermissionMap("tests/library/perm_map")
    ret = setools.InfoFlowAnalysis(compiled_policy, perm_map)
    ret._build_graph()
    return ret


@pytest.mark.obj_args("tests/library/conditionalinfoflow.conf", mls=False)
class TestConditionalInfoFlowAnalysis:

    def test_keep_conditional_rules(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Keep all conditional rules."""
        analysis.booleans = None
        analysis.rebuildgraph = True
        analysis._build_subgraph()

        source = analysis.policy.lookup_type("src")
        target = analysis.policy.lookup_type("tgt")
        flow_true = analysis.policy.lookup_type("flow_true")
        flow_false = analysis.policy.lookup_type("flow_false")

        r = analysis.G.edges[source, flow_true]["rules"]
        assert len(r) == 1
        r = analysis.G.edges[flow_true, target]["rules"]
        assert len(r) == 1
        r = analysis.G.edges[source, flow_false]["rules"]
        assert len(r) == 1
        r = analysis.G.edges[flow_false, target]["rules"]
        assert len(r) == 1

    def test_default_conditional_rules(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Keep only default conditional rules."""
        analysis.booleans = {}
        analysis.rebuildgraph = True
        analysis._build_subgraph()

        source = analysis.policy.lookup_type("src")
        target = analysis.policy.lookup_type("tgt")
        flow_true = analysis.policy.lookup_type("flow_true")
        flow_false = analysis.policy.lookup_type("flow_false")

        r = analysis.G.edges[source, flow_true]["rules"]
        assert len(r) == 0
        r = analysis.G.edges[flow_true, target]["rules"]
        assert len(r) == 0
        r = analysis.G.edges[source, flow_false]["rules"]
        assert len(r) == 1
        r = analysis.G.edges[flow_false, target]["rules"]
        assert len(r) == 1

    def test_user_conditional_true(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Keep only conditional rules selected by user specified booleans (True Case.)"""
        analysis.booleans = {"condition": True}
        analysis.rebuildgraph = True
        analysis._build_subgraph()

        source = analysis.policy.lookup_type("src")
        target = analysis.policy.lookup_type("tgt")
        flow_true = analysis.policy.lookup_type("flow_true")
        flow_false = analysis.policy.lookup_type("flow_false")

        r = analysis.G.edges[source, flow_true]["rules"]
        assert len(r) == 1
        r = analysis.G.edges[flow_true, target]["rules"]
        assert len(r) == 1
        r = analysis.G.edges[source, flow_false]["rules"]
        assert len(r) == 0
        r = analysis.G.edges[flow_false, target]["rules"]
        assert len(r) == 0

    def test_user_conditional_false(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Keep only conditional rules selected by user specified booleans (False Case.)"""
        analysis.booleans = {"condition": False}
        analysis.rebuildgraph = True
        analysis._build_subgraph()

        source = analysis.policy.lookup_type("src")
        target = analysis.policy.lookup_type("tgt")
        flow_true = analysis.policy.lookup_type("flow_true")
        flow_false = analysis.policy.lookup_type("flow_false")

        r = analysis.G.edges[source, flow_true]["rules"]
        assert len(r) == 0
        r = analysis.G.edges[flow_true, target]["rules"]
        assert len(r) == 0
        r = analysis.G.edges[source, flow_false]["rules"]
        assert len(r) == 1
        r = analysis.G.edges[flow_false, target]["rules"]
        assert len(r) == 1

    def test_remaining_edges(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Keep edges when rules are deleted, but there are still remaining rules on the edge."""
        analysis.booleans = {}
        analysis.rebuildgraph = True
        analysis._build_subgraph()

        source = analysis.policy.lookup_type("src_remain")
        target = analysis.policy.lookup_type("tgt_remain")
        flow = analysis.policy.lookup_type("flow_remain")

        r = analysis.G.edges[source, flow]["rules"]
        assert len(r) == 1
        assert str(r[0]) == 'allow src_remain flow_remain:infoflow hi_w;'
        r = analysis.G.edges[flow, target]["rules"]
        assert len(r) == 1
        assert str(r[0]) == 'allow tgt_remain flow_remain:infoflow hi_r;'
