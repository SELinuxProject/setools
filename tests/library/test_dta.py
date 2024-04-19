# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import typing

import pytest
import setools
from setools import TERuletype as TERT

from . import util


@pytest.fixture
def analysis(compiled_policy: setools.SELinuxPolicy) -> setools.DomainTransitionAnalysis:
    ret = setools.DomainTransitionAnalysis(compiled_policy)
    ret._build_graph()
    return ret


@pytest.mark.obj_args("tests/library/dta.conf")
class TestDomainTransitionAnalysis:

    def test_graph_structure(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: verify graph structure."""
        # don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        start = analysis.policy.lookup_type("start")
        trans1 = analysis.policy.lookup_type("trans1")
        trans2 = analysis.policy.lookup_type("trans2")
        trans3 = analysis.policy.lookup_type("trans3")
        trans5 = analysis.policy.lookup_type("trans5")
        dyntrans100 = analysis.policy.lookup_type("dyntrans100")
        bothtrans200 = analysis.policy.lookup_type("bothtrans200")

        edges = set(analysis.G.out_edges())
        assert set([(dyntrans100, bothtrans200),
                    (start, dyntrans100),
                    (start, trans1),
                    (trans1, trans2),
                    (trans2, trans3),
                    (trans3, trans5)]) == edges

    def test_bothtrans(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: type_transition, setexeccon(), and setcon() transitions."""

        s = analysis.policy.lookup_type("dyntrans100")
        t = analysis.policy.lookup_type("bothtrans200")
        e = analysis.policy.lookup_type("bothtrans200_exec")

        # regular transition
        r = analysis.G.edges[s, t]["transition"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, t, tclass="process",
                           perms=set(["transition", "dyntransition"]))

        # setexec perms
        r = analysis.G.edges[s, t]["setexec"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, s, tclass="process",
                           perms=set(["setexec", "setcurrent"]))

        # exec perms
        k = sorted(analysis.G.edges[s, t]["execute"].keys())
        assert k == [e]

        r = analysis.G.edges[s, t]["execute"][e]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, e, tclass="file", perms=set(["execute"]))

        # entrypoint perms
        k = sorted(analysis.G.edges[s, t]["entrypoint"].keys())
        assert k == [e]

        r = analysis.G.edges[s, t]["entrypoint"][e]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, t, e, tclass="file", perms=set(["entrypoint"]))

        # type_transition
        k = sorted(analysis.G.edges[s, t]["type_transition"].keys())
        assert k == [e]

        r = analysis.G.edges[s, t]["type_transition"][e]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.type_transition, s, e, tclass="process", default=t)

        # dynamic transition
        r = analysis.G.edges[s, t]["dyntransition"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, t, tclass="process",
                           perms=set(["transition", "dyntransition"]))

        # setcurrent
        r = analysis.G.edges[s, t]["setcurrent"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, s, tclass="process",
                           perms=set(["setexec", "setcurrent"]))

    def test_dyntrans(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: setcon() transition."""

        s = analysis.policy.lookup_type("start")
        t = analysis.policy.lookup_type("dyntrans100")

        # regular transition
        r = analysis.G.edges[s, t]["transition"]
        assert len(r) == 0

        # setexec perms
        r = analysis.G.edges[s, t]["setexec"]
        assert len(r) == 0

        # exec perms
        k = sorted(analysis.G.edges[s, t]["execute"].keys())
        assert len(k) == 0

        # entrypoint perms
        k = sorted(analysis.G.edges[s, t]["entrypoint"].keys())
        assert len(k) == 0

        # type_transition
        k = sorted(analysis.G.edges[s, t]["type_transition"].keys())
        assert len(k) == 0

        # dynamic transition
        r = analysis.G.edges[s, t]["dyntransition"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, t, tclass="process",
                           perms=set(["dyntransition"]))

        # setcurrent
        r = analysis.G.edges[s, t]["setcurrent"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, s, tclass="process",
                           perms=set(["setcurrent"]))

    def test_trans(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: type_transition transition."""

        s = analysis.policy.lookup_type("start")
        t = analysis.policy.lookup_type("trans1")
        e = analysis.policy.lookup_type("trans1_exec")

        # regular transition
        r = analysis.G.edges[s, t]["transition"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, t, tclass="process",
                           perms=set(["transition"]))

        # setexec perms
        r = analysis.G.edges[s, t]["setexec"]
        assert len(r) == 0

        # exec perms
        k = sorted(analysis.G.edges[s, t]["execute"].keys())
        assert k == [e]

        r = analysis.G.edges[s, t]["execute"][e]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, e, tclass="file",
                           perms=set(["execute"]))

        # entrypoint perms
        k = sorted(analysis.G.edges[s, t]["entrypoint"].keys())
        assert k == [e]

        r = analysis.G.edges[s, t]["entrypoint"][e]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, t, e, tclass="file",
                           perms=set(["entrypoint"]))

        # type_transition
        k = sorted(analysis.G.edges[s, t]["type_transition"].keys())
        assert k == [e]

        r = analysis.G.edges[s, t]["type_transition"][e]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.type_transition, s, e, tclass="process",
                           default=t)

        # dynamic transition
        r = analysis.G.edges[s, t]["dyntransition"]
        assert len(r) == 0

        # setcurrent
        r = analysis.G.edges[s, t]["setcurrent"]
        assert len(r) == 0

    def test_setexec(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: setexec() transition."""

        s = analysis.policy.lookup_type("trans1")
        t = analysis.policy.lookup_type("trans2")
        e = analysis.policy.lookup_type("trans2_exec")

        # regular transition
        r = analysis.G.edges[s, t]["transition"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, t, tclass="process", perms=set(["transition"]))

        # setexec perms
        r = analysis.G.edges[s, t]["setexec"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, s, tclass="process", perms=set(["setexec"]))

        # exec perms
        k = sorted(analysis.G.edges[s, t]["execute"].keys())
        assert k == [e]

        r = analysis.G.edges[s, t]["execute"][e]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, e, tclass="file", perms=set(["execute"]))

        # entrypoint perms
        k = sorted(analysis.G.edges[s, t]["entrypoint"].keys())
        assert k == [e]

        r = analysis.G.edges[s, t]["entrypoint"][e]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, t, e, tclass="file", perms=set(["entrypoint"]))

        # type_transition
        k = sorted(analysis.G.edges[s, t]["type_transition"].keys())
        assert len(k) == 0

        # dynamic transition
        r = analysis.G.edges[s, t]["dyntransition"]
        assert len(r) == 0

        # setcurrent
        r = analysis.G.edges[s, t]["setcurrent"]
        assert len(r) == 0

    def test_two_entrypoint(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: 2 entrypoints, only one by type_transition."""

        s = analysis.policy.lookup_type("trans2")
        t = analysis.policy.lookup_type("trans3")
        e = [analysis.policy.lookup_type("trans3_exec1"),
             analysis.policy.lookup_type("trans3_exec2")]

        # regular transition
        r = analysis.G.edges[s, t]["transition"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, t, tclass="process", perms=set(["transition"]))

        # setexec perms
        r = analysis.G.edges[s, t]["setexec"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, s, tclass="process", perms=set(["setexec"]))

        # exec perms
        k = sorted(analysis.G.edges[s, t]["execute"].keys())
        assert k == e

        r = analysis.G.edges[s, t]["execute"][e[0]]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, e[0], tclass="file", perms=set(["execute"]))

        r = analysis.G.edges[s, t]["execute"][e[1]]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, e[1], tclass="file", perms=set(["execute"]))

        # entrypoint perms
        k = sorted(analysis.G.edges[s, t]["entrypoint"].keys())
        assert k == e

        r = analysis.G.edges[s, t]["entrypoint"][e[0]]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, t, e[0], tclass="file", perms=set(["entrypoint"]))

        r = analysis.G.edges[s, t]["entrypoint"][e[1]]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, t, e[1], tclass="file", perms=set(["entrypoint"]))

        # type_transition
        k = sorted(analysis.G.edges[s, t]["type_transition"].keys())
        assert k == [e[0]]

        r = analysis.G.edges[s, t]["type_transition"][e[0]]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.type_transition, s, e[0], tclass="process", default=t)

        # dynamic transition
        r = analysis.G.edges[s, t]["dyntransition"]
        assert len(r) == 0

        # setcurrent
        r = analysis.G.edges[s, t]["setcurrent"]
        assert len(r) == 0

    def test_cond_type_trans(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: conditional type_transition."""

        s = analysis.policy.lookup_type("trans3")
        t = analysis.policy.lookup_type("trans5")
        e = analysis.policy.lookup_type("trans5_exec")

        # regular transition
        r = analysis.G.edges[s, t]["transition"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, t, tclass="process", perms=set(["transition"]))

        # setexec perms
        r = analysis.G.edges[s, t]["setexec"]
        assert len(r) == 0

        # exec perms
        k = sorted(analysis.G.edges[s, t]["execute"].keys())
        assert k == [e]

        r = analysis.G.edges[s, t]["execute"][e]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, s, e, tclass="file", perms=set(["execute"]))

        # entrypoint perms
        k = sorted(analysis.G.edges[s, t]["entrypoint"].keys())
        assert k == [e]

        r = analysis.G.edges[s, t]["entrypoint"][e]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, t, e, tclass="file", perms=set(["entrypoint"]))

        # type_transition
        k = sorted(analysis.G.edges[s, t]["type_transition"].keys())
        assert k == [e]

        r = analysis.G.edges[s, t]["type_transition"][e]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.type_transition, s, e, tclass="process", default=t,
                           cond="trans5", cond_block=True)

        # dynamic transition
        r = analysis.G.edges[s, t]["dyntransition"]
        assert len(r) == 0

        # setcurrent
        r = analysis.G.edges[s, t]["setcurrent"]
        assert len(r) == 0

    def test_forward_subgraph_structure(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: verify forward subgraph structure."""
        # The purpose is to ensure the subgraph is reversed
        # only when the reverse option is set, not that
        # graph reversal is correct (assumed that NetworkX
        # does it correctly).
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        analysis.reverse = False
        analysis._build_subgraph()

        start = analysis.policy.lookup_type("start")
        trans1 = analysis.policy.lookup_type("trans1")
        trans2 = analysis.policy.lookup_type("trans2")
        trans3 = analysis.policy.lookup_type("trans3")
        trans5 = analysis.policy.lookup_type("trans5")
        dyntrans100 = analysis.policy.lookup_type("dyntrans100")
        bothtrans200 = analysis.policy.lookup_type("bothtrans200")

        edges = set(analysis.subG.out_edges())
        assert set([(dyntrans100, bothtrans200),
                    (start, dyntrans100),
                    (start, trans1),
                    (trans1, trans2),
                    (trans2, trans3),
                    (trans3, trans5)]) == edges

    def test_reverse_subgraph_structure(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: verify reverse subgraph structure."""
        # The purpose is to ensure the subgraph is reversed
        # only when the reverse option is set, not that
        # graph reversal is correct (assumed that NetworkX
        # does it correctly).
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        analysis.reverse = True
        analysis._build_subgraph()

        start = analysis.policy.lookup_type("start")
        trans1 = analysis.policy.lookup_type("trans1")
        trans2 = analysis.policy.lookup_type("trans2")
        trans3 = analysis.policy.lookup_type("trans3")
        trans5 = analysis.policy.lookup_type("trans5")
        dyntrans100 = analysis.policy.lookup_type("dyntrans100")
        bothtrans200 = analysis.policy.lookup_type("bothtrans200")

        edges = set(analysis.subG.out_edges())
        assert set([(bothtrans200, dyntrans100),
                    (dyntrans100, start),
                    (trans1, start),
                    (trans2, trans1),
                    (trans3, trans2),
                    (trans5, trans3)]) == edges

    def test_exclude_domain(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: exclude domain type."""
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        analysis.reverse = False
        analysis.exclude = ["trans1"]  # type: ignore[list-item]
        analysis._build_subgraph()

        start = analysis.policy.lookup_type("start")
        trans2 = analysis.policy.lookup_type("trans2")
        trans3 = analysis.policy.lookup_type("trans3")
        trans5 = analysis.policy.lookup_type("trans5")
        dyntrans100 = analysis.policy.lookup_type("dyntrans100")
        bothtrans200 = analysis.policy.lookup_type("bothtrans200")

        edges = set(analysis.subG.out_edges())
        assert set([(dyntrans100, bothtrans200),
                    (start, dyntrans100),
                    (trans2, trans3),
                    (trans3, trans5)]) == edges

    def test_exclude_entryoint_with_2entrypoints(
            self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: exclude entrypoint type without transition deletion (other entrypoints)."""
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        analysis.reverse = False
        analysis.exclude = ["trans3_exec1"]  # type: ignore[list-item]
        analysis._build_subgraph()

        start = analysis.policy.lookup_type("start")
        trans1 = analysis.policy.lookup_type("trans1")
        trans2 = analysis.policy.lookup_type("trans2")
        trans3 = analysis.policy.lookup_type("trans3")
        trans5 = analysis.policy.lookup_type("trans5")
        dyntrans100 = analysis.policy.lookup_type("dyntrans100")
        bothtrans200 = analysis.policy.lookup_type("bothtrans200")

        edges = set(analysis.subG.out_edges())
        assert set([(dyntrans100, bothtrans200),
                    (start, dyntrans100),
                    (start, trans1),
                    (trans1, trans2),
                    (trans2, trans3),
                    (trans3, trans5)]) == edges

    def test_exclude_entryoint_with_dyntrans(
            self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: exclude entrypoint type without transition deletion (dyntrans)."""
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        analysis.reverse = False
        analysis.exclude = ["bothtrans200_exec"]  # type: ignore[list-item]
        analysis._build_subgraph()

        start = analysis.policy.lookup_type("start")
        trans1 = analysis.policy.lookup_type("trans1")
        trans2 = analysis.policy.lookup_type("trans2")
        trans3 = analysis.policy.lookup_type("trans3")
        trans5 = analysis.policy.lookup_type("trans5")
        dyntrans100 = analysis.policy.lookup_type("dyntrans100")
        bothtrans200 = analysis.policy.lookup_type("bothtrans200")

        edges = set(analysis.subG.out_edges())
        assert set([(dyntrans100, bothtrans200),
                    (start, dyntrans100),
                    (start, trans1),
                    (trans1, trans2),
                    (trans2, trans3),
                    (trans3, trans5)]) == edges

    def test_exclude_entryoint_delete_transition(
            self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: exclude entrypoint type with transition deletion."""
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        analysis.reverse = False
        analysis.exclude = ["trans2_exec"]  # type: ignore[list-item]
        analysis._build_subgraph()

        start = analysis.policy.lookup_type("start")
        trans1 = analysis.policy.lookup_type("trans1")
        trans2 = analysis.policy.lookup_type("trans2")
        trans3 = analysis.policy.lookup_type("trans3")
        trans5 = analysis.policy.lookup_type("trans5")
        dyntrans100 = analysis.policy.lookup_type("dyntrans100")
        bothtrans200 = analysis.policy.lookup_type("bothtrans200")

        edges = set(analysis.subG.out_edges())
        assert set([(dyntrans100, bothtrans200),
                    (start, dyntrans100),
                    (start, trans1),
                    (trans2, trans3),
                    (trans3, trans5)]) == edges

    def test_all_paths(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all paths output"""
        analysis.reverse = False
        analysis.exclude = []
        analysis.source = "start"
        analysis.target = "bothtrans200"
        analysis.depth_limit = 3
        analysis.mode = setools.DomainTransitionAnalysis.Mode.AllPaths

        expected_path = ["start", "dyntrans100", "bothtrans200"]

        paths = list(analysis.results())
        assert 1 == len(paths)

        for path in paths:
            for stepnum, step in enumerate(typing.cast(setools.DTAPath, path)):
                assert isinstance(step.source, setools.Type)
                assert isinstance(step.target, setools.Type)
                assert expected_path[stepnum] == step.source
                assert expected_path[stepnum + 1] == step.target

                for r in step.transition:
                    assert "transition" in r.perms

                for e in step.entrypoints:
                    assert isinstance(e.name, setools.Type)

                    for r in e.entrypoint:
                        assert "entrypoint" in r.perms

                    for r in e.execute:
                        assert "execute" in r.perms

                    for r in e.type_transition:
                        assert TERT.type_transition == r.ruletype

                for r in step.setexec:
                    assert "setexec" in r.perms

                for r in step.dyntransition:
                    assert "dyntransition" in r.perms

                for r in step.setcurrent:
                    assert "setcurrent" in r.perms

    def test_all_shortest_paths(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all shortest paths output"""
        analysis.reverse = False
        analysis.exclude = []
        analysis.source = "start"
        analysis.target = "bothtrans200"
        analysis.mode = setools.DomainTransitionAnalysis.Mode.ShortestPaths

        expected_path = ["start", "dyntrans100", "bothtrans200"]

        paths = list(analysis.results())
        assert 1 == len(paths)

        for path in paths:
            for stepnum, step in enumerate(typing.cast(setools.DTAPath, path)):
                assert isinstance(step.source, setools.Type)
                assert isinstance(step.target, setools.Type)
                assert expected_path[stepnum] == step.source
                assert expected_path[stepnum + 1] == step.target

                for r in step.transition:
                    assert "transition" in r.perms

                for e in step.entrypoints:
                    assert isinstance(e.name, setools.Type)

                    for r in e.entrypoint:
                        assert "entrypoint" in r.perms

                    for r in e.execute:
                        assert "execute" in r.perms

                    for r in e.type_transition:
                        assert TERT.type_transition == r.ruletype

                for r in step.setexec:
                    assert "setexec" in r.perms

                for r in step.dyntransition:
                    assert "dyntransition" in r.perms

                for r in step.setcurrent:
                    assert "setcurrent" in r.perms

    def test_transitions(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: transitions output"""
        analysis.reverse = False
        analysis.exclude = []
        analysis.source = "start"
        analysis.depth_limit = 1
        analysis.mode = setools.DomainTransitionAnalysis.Mode.TransitionsOut

        transitions = list(analysis.results())
        assert 2 == len(transitions)

        for step in transitions:
            assert isinstance(step, setools.DomainTransition)
            assert isinstance(step.source, setools.Type)
            assert isinstance(step.target, setools.Type)
            assert "start" == step.source

            for r in step.transition:
                assert "transition" in r.perms

            for e in step.entrypoints:
                assert isinstance(e.name, setools.Type)

                for r in e.entrypoint:
                    assert "entrypoint" in r.perms

                for r in e.execute:
                    assert "execute" in r.perms

                for r in e.type_transition:
                    assert TERT.type_transition == r.ruletype

            for r in step.setexec:
                assert "setexec" in r.perms

            for r in step.dyntransition:
                assert "dyntransition" in r.perms

            for r in step.setcurrent:
                assert "setcurrent" in r.perms

    def test_all_paths_reversed(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all paths output reverse DTA"""
        analysis.reverse = True
        analysis.exclude = []
        analysis.source = "bothtrans200"
        analysis.target = "start"
        analysis.depth_limit = 3
        analysis.mode = setools.DomainTransitionAnalysis.Mode.AllPaths

        expected_path = ["bothtrans200", "dyntrans100", "start"]

        paths = list(analysis.results())
        assert 1 == len(paths)

        for path in paths:
            for stepnum, step in enumerate(typing.cast(setools.DTAPath, path)):
                assert isinstance(step.source, setools.Type)
                assert isinstance(step.target, setools.Type)
                assert step.source == expected_path[stepnum + 1]
                assert step.target == expected_path[stepnum]

                for r in step.transition:
                    assert "transition" in r.perms

                for e in step.entrypoints:
                    assert isinstance(e.name, setools.Type)

                    for r in e.entrypoint:
                        assert "entrypoint" in r.perms

                    for r in e.execute:
                        assert "execute" in r.perms

                    for r in e.type_transition:
                        assert TERT.type_transition == r.ruletype

                for r in step.setexec:
                    assert "setexec" in r.perms

                for r in step.dyntransition:
                    assert "dyntransition" in r.perms

                for r in step.setcurrent:
                    assert "setcurrent" in r.perms

    def test_all_shortest_paths_reversed(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all shortest paths output reverse DTA"""
        analysis.reverse = True
        analysis.exclude = []
        analysis.source = "bothtrans200"
        analysis.target = "start"
        analysis.mode = setools.DomainTransitionAnalysis.Mode.ShortestPaths

        expected_path = ["bothtrans200", "dyntrans100", "start"]

        paths = list(analysis.results())
        assert 1 == len(paths)

        for path in paths:
            for stepnum, step in enumerate(typing.cast(setools.DTAPath, path)):
                assert isinstance(step.source, setools.Type)
                assert isinstance(step.target, setools.Type)
                assert step.source == expected_path[stepnum + 1]
                assert step.target == expected_path[stepnum]

                for r in step.transition:
                    assert "transition" in r.perms

                for e in step.entrypoints:
                    assert isinstance(e.name, setools.Type)

                    for r in e.entrypoint:
                        assert "entrypoint" in r.perms

                    for r in e.execute:
                        assert "execute" in r.perms

                    for r in e.type_transition:
                        assert TERT.type_transition == r.ruletype

                for r in step.setexec:
                    assert "setexec" in r.perms

                for r in step.dyntransition:
                    assert "dyntransition" in r.perms

                for r in step.setcurrent:
                    assert "setcurrent" in r.perms

    def test_transitions_reversed(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: transitions output reverse DTA"""
        analysis.reverse = False
        analysis.exclude = []
        analysis.target = "bothtrans200"
        analysis.depth_limit = 1
        analysis.mode = setools.DomainTransitionAnalysis.Mode.TransitionsIn

        transitions = list(analysis.results())
        assert 1 == len(transitions)

        for step in transitions:
            assert isinstance(step, setools.DomainTransition)
            assert isinstance(step.source, setools.Type)
            assert isinstance(step.target, setools.Type)
            assert "bothtrans200" == step.target

            for r in step.transition:
                assert "transition" in r.perms

            for e in step.entrypoints:
                assert isinstance(e.name, setools.Type)

                for r in e.entrypoint:
                    assert "entrypoint" in r.perms

                for r in e.execute:
                    assert "execute" in r.perms

                for r in e.type_transition:
                    assert TERT.type_transition == r.ruletype

            for r in step.setexec:
                assert "setexec" in r.perms

            for r in step.dyntransition:
                assert "dyntransition" in r.perms

            for r in step.setcurrent:
                assert "setcurrent" in r.perms

    def test_set_exclude_invalid_type(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: set invalid excluded type."""
        analysis.reverse = False
        analysis.exclude = []
        with pytest.raises(setools.exception.InvalidType):
            analysis.exclude = ["trans1", "invalid_type"]  # type: ignore[list-item]

    def test_all_paths_invalid_source(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all paths with invalid source type."""
        analysis.reverse = False
        analysis.exclude = []
        analysis.mode = setools.DomainTransitionAnalysis.Mode.AllPaths
        with pytest.raises(setools.exception.InvalidType):
            analysis.source = "invalid_type"

    def test_all_paths_invalid_target(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all paths with invalid target type."""
        analysis.reverse = False
        analysis.exclude = []
        analysis.mode = setools.DomainTransitionAnalysis.Mode.AllPaths
        with pytest.raises(setools.exception.InvalidType):
            analysis.target = "invalid_type"

    def test_all_paths_invalid_maxlen(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all paths with invalid max path length."""
        analysis.reverse = False
        analysis.exclude = []
        analysis.mode = setools.DomainTransitionAnalysis.Mode.AllPaths
        with pytest.raises(ValueError):
            analysis.depth_limit = -2

    def test_all_paths_source_excluded(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all paths with excluded source type."""
        analysis.reverse = False
        analysis.exclude = ["trans1"]  # type: ignore[list-item]
        analysis.source = "trans1"
        analysis.target = "trans2"
        analysis.mode = setools.DomainTransitionAnalysis.Mode.AllPaths
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_paths_target_excluded(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all paths with excluded target type."""
        analysis.reverse = False
        analysis.exclude = ["trans2"]  # type: ignore[list-item]
        analysis.source = "trans1"
        analysis.target = "trans2"
        analysis.mode = setools.DomainTransitionAnalysis.Mode.AllPaths
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_paths_source_disconnected(
            self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all paths with disconnected source type."""
        analysis.reverse = False
        analysis.exclude = []
        analysis.source = "trans5"
        analysis.target = "trans2"
        analysis.mode = setools.DomainTransitionAnalysis.Mode.AllPaths
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_paths_target_disconnected(
            self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all paths with disconnected target type."""
        analysis.reverse = False
        analysis.exclude = ["trans3"]  # type: ignore[list-item]
        analysis.source = "trans2"
        analysis.target = "trans5"
        analysis.mode = setools.DomainTransitionAnalysis.Mode.AllPaths
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_shortest_path_target_disconnected(
            self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: shortest path with disconnected target type."""
        analysis.reverse = False
        analysis.exclude = ["trans3"]  # type: ignore[list-item]
        analysis.source = "trans2"
        analysis.target = "trans5"
        analysis.mode = setools.DomainTransitionAnalysis.Mode.ShortestPaths
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_shortest_paths_source_excluded(
            self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all shortest paths with excluded source type."""
        analysis.reverse = False
        analysis.exclude = ["trans1"]  # type: ignore[list-item]
        analysis.source = "trans1"
        analysis.target = "trans2"
        analysis.mode = setools.DomainTransitionAnalysis.Mode.ShortestPaths
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_shortest_paths_target_excluded(
            self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all shortest paths with excluded target type."""
        analysis.reverse = False
        analysis.exclude = ["trans2"]  # type: ignore[list-item]
        analysis.source = "trans1"
        analysis.target = "trans2"
        analysis.mode = setools.DomainTransitionAnalysis.Mode.ShortestPaths
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_shortest_paths_source_disconnected(
            self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all shortest paths with disconnected source type."""
        analysis.reverse = False
        analysis.exclude = []
        analysis.source = "trans5"
        analysis.target = "trans2"
        analysis.mode = setools.DomainTransitionAnalysis.Mode.ShortestPaths
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_shortest_paths_target_disconnected(
            self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: all shortest paths with disconnected target type."""
        analysis.reverse = False
        analysis.exclude = ["trans3"]  # type: ignore[list-item]
        analysis.source = "trans2"
        analysis.target = "trans5"
        analysis.mode = setools.DomainTransitionAnalysis.Mode.ShortestPaths
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_transitions_source_excluded(self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: transitions with excluded source type."""
        analysis.reverse = False
        analysis.exclude = ["trans1"]  # type: ignore[list-item]
        analysis.mode = setools.DomainTransitionAnalysis.Mode.TransitionsOut
        analysis.source = "trans1"
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_transitions_source_disconnected(
            self, analysis: setools.DomainTransitionAnalysis) -> None:
        """DTA: transitions with disconnected source type."""
        analysis.reverse = False
        analysis.exclude = ["trans3"]  # type: ignore[list-item]
        analysis.source = "trans5"
        analysis.mode = setools.DomainTransitionAnalysis.Mode.TransitionsOut
        paths = list(analysis.results())
        assert 0 == len(paths)
