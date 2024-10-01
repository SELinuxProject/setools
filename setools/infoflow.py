# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import enum
import itertools
import logging
from collections.abc import Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass, InitVar
import typing

try:
    import networkx as nx
    from networkx.exception import NetworkXError, NetworkXNoPath, NodeNotFound

except ImportError as iex:
    logging.getLogger(__name__).debug(f"{iex.name} failed to import.")

from . import exception, mixins, permmap, policyrep, query
from .descriptors import CriteriaDescriptor, EdgeAttrIntMax, EdgeAttrList

InfoFlowPath = Iterable['InfoFlowStep']

__all__: typing.Final[tuple[str, ...]] = ("InfoFlowAnalysis", "InfoFlowStep", "InfoFlowPath")


class InfoFlowAnalysis(query.DirectedGraphAnalysis):

    """
    Information flow analysis.

    Parameters:
    policy      The policy to analyze.
    perm_map    The permission map or path to the permission map file.

    Keyword Parameters
    source      The source type of the analysis.
    target      The target type of the analysis.
    mode        The analysis mode (see InfoFlowAnalysisMode)
    min_weight  The minimum permission weight to include in the analysis.
                (default is 1)
    exclude     The types excluded from the information flow analysis.
                (default is none)
    booleans    If None, all rules will be added to the analysis (default).
                otherwise it should be set to a dict with keys corresponding
                to boolean names and values of True/False. Any unspecified
                booleans will use the policy's default values.

    """

    class Mode(enum.Enum):

        """Information flow analysis modes"""

        ShortestPaths = "All shortest paths"
        AllPaths = "All paths up to"  # N steps
        FlowsOut = "Flows out of the source type."
        FlowsIn = "Flows into the target type."

    DIRECT_MODES: typing.Final[tuple[Mode, ...]] = (Mode.FlowsIn, Mode.FlowsOut)
    TRANSITIVE_MODES: typing.Final[tuple[Mode, ...]] = (Mode.ShortestPaths, Mode.AllPaths)

    source = CriteriaDescriptor[policyrep.Type](lookup_function="lookup_type")
    target = CriteriaDescriptor[policyrep.Type](lookup_function="lookup_type")
    mode = Mode.ShortestPaths
    booleans: Mapping[str, bool] | None

    def __init__(self, policy: policyrep.SELinuxPolicy, perm_map: permmap.PermissionMap, /, *,
                 min_weight: int = 1,
                 source: policyrep.Type | str | None = None,
                 target: policyrep.Type | str | None = None,
                 mode: Mode = Mode.ShortestPaths,
                 depth_limit: int | None = 1,
                 exclude: Iterable[policyrep.Type | str] | None = None,
                 booleans: Mapping[str, bool] | None = None) -> None:

        super().__init__(policy, perm_map=perm_map, min_weight=min_weight, source=source,
                         target=target, mode=mode, depth_limit=depth_limit,
                         exclude=exclude, booleans=booleans)

        self._min_weight: int
        self._perm_map: permmap.PermissionMap
        self._depth_limit: int | None

        self.rebuildgraph = True
        self.rebuildsubgraph = True

        try:
            self.G = nx.DiGraph()
            self.subG = self.G.copy()
        except NameError:
            self.log.critical("NetworkX is not available.  This is "
                              "required for Information Flow Analysis.")
            self.log.critical("This is typically in the python3-networkx package.")
            raise

    @property
    def depth_limit(self) -> int | None:
        return self._depth_limit

    @depth_limit.setter
    def depth_limit(self, value: int | None) -> None:
        if value is not None and value < 1:
            raise ValueError("Information flow max depth must be positive.")

        self._depth_limit = value
        # no subgraph rebuild needed.

    @property
    def min_weight(self) -> int:
        return self._min_weight

    @min_weight.setter
    def min_weight(self, weight: int) -> None:
        if not 1 <= weight <= 10:
            raise ValueError(
                "Min information flow weight must be an integer 1-10.")

        self._min_weight = weight
        self.rebuildsubgraph = True

    @property
    def perm_map(self) -> permmap.PermissionMap:
        return self._perm_map

    @perm_map.setter
    def perm_map(self, perm_map: permmap.PermissionMap) -> None:
        self._perm_map = perm_map
        self.rebuildgraph = True
        self.rebuildsubgraph = True

    @property
    def exclude(self) -> list[policyrep.Type]:
        return self._exclude

    @exclude.setter
    def exclude(self, types: Iterable[policyrep.Type | str] | None) -> None:
        if types:
            self._exclude: list[policyrep.Type] = [self.policy.lookup_type(t) for t in types]
        else:
            self._exclude = []

        self.rebuildsubgraph = True

    def results(self) -> Iterable[InfoFlowPath] | Iterable["InfoFlowStep"]:
        if self.rebuildsubgraph:
            self._build_subgraph()

        self.log.info(f"Generating information flow results from {self.policy}")
        self.log.debug(f"{self.source=}")
        self.log.debug(f"{self.target=}")
        self.log.debug(f"{self.mode=}, {self.depth_limit=}")

        with suppress(NetworkXNoPath, NodeNotFound, NetworkXError):
            match self.mode:
                case InfoFlowAnalysis.Mode.ShortestPaths:
                    if not all((self.source, self.target)):
                        raise ValueError("Source and target types must be specified.")

                    self.log.info("Generating all shortest information flow paths from "
                                  f"{self.source} to {self.target}...")

                    for path in nx.all_shortest_paths(self.subG, self.source, self.target):
                        yield (InfoFlowStep(self.subG, source, target)
                               for source, target in nx.utils.misc.pairwise(path))

                case InfoFlowAnalysis.Mode.AllPaths:
                    if not all((self.source, self.target)):
                        raise ValueError("Source and target types must be specified.")

                    self.log.info("Generating all information flow paths from "
                                  f"{self.source} to {self.target}, "
                                  f"max length {self.depth_limit}...")

                    for path in nx.all_simple_paths(self.subG, self.source, self.target,
                                                    cutoff=self.depth_limit):
                        yield (InfoFlowStep(self.subG, source, target)
                               for source, target in nx.utils.misc.pairwise(path))

                case InfoFlowAnalysis.Mode.FlowsOut:
                    if not self.source:
                        raise ValueError("Source type must be specified.")

                    self.log.info(f"Generating all information flows out of {self.source}, "
                                  f"max depth {self.depth_limit}")
                    for source, target in nx.bfs_edges(self.subG, self.source,
                                                       depth_limit=self.depth_limit):
                        yield InfoFlowStep(self.subG, source, target)

                case InfoFlowAnalysis.Mode.FlowsIn:
                    if not self.target:
                        raise ValueError("Target type must be specified.")

                    self.log.info(f"Generating all information flows into {self.target} ",
                                  f"max depth {self.depth_limit}")
                    # swap source and target since bfs_edges is reversed.
                    for target, source in nx.bfs_edges(self.subG, self.target, reverse=True,
                                                       depth_limit=self.depth_limit):
                        yield InfoFlowStep(self.subG, source, target)

                case _:
                    raise ValueError(f"Unknown analysis mode: {self.mode}")

    def graphical_results(self) -> "nx.DiGraph":

        """
        Return the results of the analysis as a NetworkX directed graph.
        Caller has the responsibility of converting the graph to a
        visualization.

        For example, to convert to a pygraphviz graph:
            pgv = nx.nx_agraph.to_agraph(g.graphical_results())
            pgv.layout(prog="dot")
        """

        if self.rebuildsubgraph:
            self._build_subgraph()

        self.log.info(f"Generating graphical information flow results from {self.policy}")
        self.log.debug(f"{self.source=}")
        self.log.debug(f"{self.target=}")
        self.log.debug(f"{self.mode=}, {self.depth_limit=}")

        try:
            match self.mode:
                case InfoFlowAnalysis.Mode.ShortestPaths:
                    if not all((self.source, self.target)):
                        raise ValueError("Source and target types must be specified.")

                    self.log.info("Generating all shortest information flow paths from "
                                  f"{self.source} to {self.target}...")
                    paths = nx.all_shortest_paths(self.subG, self.source, self.target)
                    edges = [pair for path in paths for pair in nx.utils.misc.pairwise(path)]

                    out = nx.DiGraph()
                    out.add_edges_from(edges)
                    return out

                case InfoFlowAnalysis.Mode.AllPaths:
                    if not all((self.source, self.target)):
                        raise ValueError("Source and target types must be specified.")

                    self.log.info("Generating all information flow paths from "
                                  f"{self.source} to {self.target}, "
                                  f"max length {self.depth_limit}...")
                    paths = nx.all_simple_paths(self.subG, self.source, self.target,
                                                cutoff=self.depth_limit)
                    edges = [pair for path in paths for pair in nx.utils.misc.pairwise(path)]

                    out = nx.DiGraph()
                    out.add_edges_from(edges)
                    return out

                case InfoFlowAnalysis.Mode.FlowsOut:
                    if not self.source:
                        raise ValueError("Source type must be specified.")

                    self.log.info(f"Generating all information flows out of {self.source}, "
                                  f"max depth {self.depth_limit}")
                    return nx.bfs_tree(self.subG, self.source, depth_limit=self.depth_limit)

                case InfoFlowAnalysis.Mode.FlowsIn:
                    if not self.target:
                        raise ValueError("Target type must be specified.")

                    self.log.info(f"Generating all information flows into {self.target} ",
                                  f"max depth {self.depth_limit}")
                    out = nx.bfs_tree(self.subG, self.target, reverse=True,
                                      depth_limit=self.depth_limit)
                    # output is reversed, un-reverse it
                    return nx.reverse(out, copy=False)

                case _:
                    raise ValueError(f"Unknown analysis mode: {self.mode}")

        except Exception as ex:
            raise exception.AnalysisException(
                f"Unable to generate graphical results: {ex}") from ex

    def get_stats(self) -> str:  # pragma: no cover
        """
        Get the information flow graph statistics.

        Return: str
        """
        if self.rebuildgraph:
            self._build_graph()

        return f"{nx.number_of_nodes(self.G)=}\n" \
               f"{nx.number_of_edges(self.G)=}\n" \
               f"{len(self.G)=}\n"

    #
    # Internal functions follow
    #

    def _generate_steps(self, path: list[policyrep.Type]) -> InfoFlowPath:
        """
        Generator which returns the source, target, and associated rules
        for each information flow step.

        Parameter:
        path   A list of graph node names representing an information flow path.

        Yield: tuple(source, target, rules)

        source  The source type for this step of the information flow.
        target  The target type for this step of the information flow.
        rules   The list of rules creating this information flow step.
        """
        for source, target in nx.utils.misc.pairwise(path):
            yield InfoFlowStep(self.subG, source, target)

    #
    #
    # Graph building functions
    #
    #
    # 1. _build_graph determines the flow in each direction for each TE
    #    rule and then expands the rule.  All information flows are
    #    included in this main graph: memory is traded off for efficiency
    #    as the main graph should only need to be rebuilt if permission
    #    weights change.
    # 2. _build_subgraph derives a subgraph which removes all excluded
    #    types (nodes) and edges (information flows) which are below the
    #    minimum weight. This subgraph is rebuilt only if the main graph
    #    is rebuilt or the minimum weight or excluded types change.

    def _build_graph(self) -> None:
        self.G.clear()
        self.G.name = f"Information flow graph for {self.policy}."

        self.perm_map.map_policy(self.policy)

        self.log.info(f"Building information flow graph from {self.policy}...")
        self.log.debug(f"{self.perm_map=}")

        for rule in self.policy.terules():
            if rule.ruletype != policyrep.TERuletype.allow:
                continue

            weight = self.perm_map.rule_weight(typing.cast(policyrep.AVRule, rule))

            for s, t in itertools.product(rule.source.expand(), rule.target.expand()):
                # only add flows if they actually flow
                # in or out of the source type type
                if s != t:
                    if weight.write:
                        edge = InfoFlowStep(self.G, s, t, create=True)
                        edge.rules.append(rule)
                        edge.weight = weight.write

                    if weight.read:
                        edge = InfoFlowStep(self.G, t, s, create=True)
                        edge.rules.append(rule)
                        edge.weight = weight.read

        self.rebuildgraph = False
        self.rebuildsubgraph = True
        self.log.info("Completed building information flow graph.")
        self.log.debug(f"Graph stats: nodes: {nx.number_of_nodes(self.G)}, "
                       f"edges: {nx.number_of_edges(self.G)}.")

    def _build_subgraph(self) -> None:
        if self.rebuildgraph:
            self._build_graph()

        self.log.info("Building information flow subgraph...")
        self.log.debug(f"{self.min_weight=}")
        self.log.debug(f"{self.exclude=}")
        self.log.debug(f"{self.booleans=}")

        # delete excluded types from subgraph
        nodes = [n for n in self.G.nodes() if n not in self.exclude]
        self.subG = self.G.subgraph(nodes).copy()

        # delete edges below minimum weight.
        # no need if weight is 1, since that
        # does not exclude any edges.
        if self.min_weight > 1:
            delete_list = []
            for s, t in self.subG.edges():
                edge = InfoFlowStep(self.subG, s, t)
                if edge.weight < self.min_weight:
                    delete_list.append(edge)

            self.subG.remove_edges_from(delete_list)

        if self.booleans is not None:
            delete_list = []
            for s, t in self.subG.edges():
                edge = InfoFlowStep(self.subG, s, t)

                # collect disabled rules
                rule_list = []
                # pylint: disable=not-an-iterable
                for rule in edge.rules:
                    if not rule.enabled(**self.booleans):
                        rule_list.append(rule)

                deleted_rules: list[policyrep.AVRule] = []
                for rule in rule_list:
                    if rule not in deleted_rules:
                        edge.rules.remove(rule)
                        deleted_rules.append(rule)

                if not edge.rules:
                    delete_list.append(edge)

            self.subG.remove_edges_from(delete_list)

        self.rebuildsubgraph = False
        self.log.info("Completed building information flow subgraph.")
        self.log.debug(f"Subgraph stats: nodes: {nx.number_of_nodes(self.subG)}, "
                       f"edges: {nx.number_of_edges(self.subG)}.")


@dataclass
class InfoFlowStep(mixins.NetworkXGraphEdge):

    """
    A graph edge.  Also used for returning information flow steps.

    Parameters:
    graph       The NetworkX graph.
    source      The source type of the edge.
    target      The target type of the edge.

    Keyword Parameters:
    create      (T/F) create the edge if it does not exist.
                The default is False.
    """

    G: "nx.DiGraph"
    source: policyrep.Type
    target: policyrep.Type
    create: InitVar[bool] = False
    rules = EdgeAttrList()

    # use capacity to store the info flow weight so
    # we can use network flow algorithms naturally.
    # The weight for each edge is 1 since each info
    # flow step is no more costly than another
    # (see below add_edge() call)
    weight = EdgeAttrIntMax('capacity')

    def __post_init__(self, create) -> None:
        if not self.G.has_edge(self.source, self.target):
            if create:
                self.G.add_edge(self.source, self.target, weight=1)
                self.rules = None
                self.weight = None
            else:
                raise ValueError("InfoFlowStep does not exist in graph")

    def __format__(self, spec: str) -> str:
        if spec == "full":
            rules = "\n".join(f"   {r}" for r in sorted(self.rules))
            return f"{self.source} -> {self.target}\n{rules}"
        elif not spec:
            return f"{self.source} -> {self.target}"
        else:
            return super().__format__(spec)

    def __str__(self):
        return self.__format__("full")
