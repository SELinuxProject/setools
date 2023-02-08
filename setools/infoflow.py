# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import itertools
import logging
from contextlib import suppress
from typing import cast, Iterable, List, Mapping, Optional, Union

try:
    import networkx as nx
    from networkx.exception import NetworkXError, NetworkXNoPath, NodeNotFound
except ImportError:
    logging.getLogger(__name__).debug("NetworkX failed to import.")

from .descriptors import EdgeAttrIntMax, EdgeAttrList
from .permmap import PermissionMap
from .policyrep import AVRule, SELinuxPolicy, TERuletype, Type

__all__ = ['InfoFlowAnalysis']

InfoFlowPath = Iterable['InfoFlowStep']


class InfoFlowAnalysis:

    """Information flow analysis."""

    _exclude: List[Type]
    _min_weight: int
    _perm_map: PermissionMap

    def __init__(self, policy: SELinuxPolicy, perm_map: PermissionMap, min_weight: int = 1,
                 exclude: Optional[Iterable[Union[Type, str]]] = None,
                 booleans: Optional[Mapping[str, bool]] = None) -> None:
        """
        Parameters:
        policy      The policy to analyze.
        perm_map    The permission map or path to the permission map file.
        minweight   The minimum permission weight to include in the analysis.
                    (default is 1)
        exclude     The types excluded from the information flow analysis.
                    (default is none)
        booleans    If None, all rules will be added to the analysis (default).
                    otherwise it should be set to a dict with keys corresponding
                    to boolean names and values of True/False. Any unspecified
                    booleans will use the policy's default values.
        """
        self.log = logging.getLogger(__name__)

        self.policy = policy

        self.min_weight = min_weight
        self.perm_map = perm_map
        self.exclude = exclude  # type: ignore # https://github.com/python/mypy/issues/220
        self.booleans = booleans
        self.rebuildgraph = True
        self.rebuildsubgraph = True

        try:
            self.G = nx.DiGraph()
            self.subG = self.G.copy()
        except NameError:
            self.log.critical("NetworkX is not available.  This is "
                              "requried for Information Flow Analysis.")
            self.log.critical("This is typically in the python3-networkx package.")
            raise

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
    def perm_map(self) -> PermissionMap:
        return self._perm_map

    @perm_map.setter
    def perm_map(self, perm_map: PermissionMap) -> None:
        self._perm_map = perm_map
        self.rebuildgraph = True
        self.rebuildsubgraph = True

    @property
    def exclude(self) -> List[Type]:
        return self._exclude

    @exclude.setter
    def exclude(self, types: Optional[Iterable[Union[Type, str]]]) -> None:
        if types:
            self._exclude: List[Type] = [self.policy.lookup_type(t) for t in types]
        else:
            self._exclude = []

        self.rebuildsubgraph = True

    def shortest_path(self, source: Type, target: Type) -> Iterable[InfoFlowPath]:
        """
        Generator which yields one shortest path between the source
        and target types (there may be more).

        Parameters:
        source   The source type.
        target   The target type.

        Yield: generator(steps)

        steps Yield: tuple(source, target, rules)

        source   The source type for this step of the information flow.
        target   The target type for this step of the information flow.
        rules    The list of rules creating this information flow step.
        """
        s = self.policy.lookup_type(source)
        t = self.policy.lookup_type(target)

        if self.rebuildsubgraph:
            self._build_subgraph()

        self.log.info("Generating one shortest information flow path from {0} to {1}...".
                      format(s, t))

        with suppress(NetworkXNoPath, NodeNotFound):
            # NodeNotFound: the type is valid but not in graph, e.g.
            # excluded or disconnected due to min weight
            # NetworkXNoPath: no paths or the target type is
            # not in the graph
            # pylint: disable=unexpected-keyword-arg, no-value-for-parameter
            yield self.__generate_steps(nx.shortest_path(self.subG, source=s, target=t))

    def all_paths(self, source: Union[Type, str], target: Union[Type, str], maxlen: int = 2) \
            -> Iterable[InfoFlowPath]:
        """
        Generator which yields all paths between the source and target
        up to the specified maximum path length.  This algorithm
        tends to get very expensive above 3-5 steps, depending
        on the policy complexity.

        Parameters:
        source    The source type.
        target    The target type.
        maxlen    Maximum length of paths.

        Yield: generator(steps)

        steps Yield: tuple(source, target, rules)

        source    The source type for this step of the information flow.
        target    The target type for this step of the information flow.
        rules     The list of rules creating this information flow step.
        """
        if maxlen < 1:
            raise ValueError("Maximum path length must be positive.")

        s = self.policy.lookup_type(source)
        t = self.policy.lookup_type(target)

        if self.rebuildsubgraph:
            self._build_subgraph()

        self.log.info("Generating all information flow paths from {0} to {1}, max length {2}...".
                      format(s, t, maxlen))

        with suppress(NetworkXNoPath, NodeNotFound):
            # NodeNotFound: the type is valid but not in graph, e.g.
            # excluded or disconnected due to min weight
            # NetworkXNoPath: no paths or the target type is
            # not in the graph
            for path in nx.all_simple_paths(self.subG, s, t, maxlen):
                yield self.__generate_steps(path)

    def all_shortest_paths(self, source: Union[Type, str], target: Union[Type, str]) \
            -> Iterable[InfoFlowPath]:
        """
        Generator which yields all shortest paths between the source
        and target types.

        Parameters:
        source   The source type.
        target   The target type.

        Yield: generator(steps)

        steps Yield: tuple(source, target, rules)

        source   The source type for this step of the information flow.
        target   The target type for this step of the information flow.
        rules    The list of rules creating this information flow step.
        """
        s = self.policy.lookup_type(source)
        t = self.policy.lookup_type(target)

        if self.rebuildsubgraph:
            self._build_subgraph()

        self.log.info("Generating all shortest information flow paths from {0} to {1}...".
                      format(s, t))

        with suppress(NetworkXNoPath, NodeNotFound):
            # NodeNotFound: the type is valid but not in graph, e.g.
            # excluded or disconnected due to min weight
            # NetworkXNoPath: no paths or the target type is
            # not in the graph
            for path in nx.all_shortest_paths(self.subG, s, t):
                yield self.__generate_steps(path)

    def infoflows(self, type_: Union[Type, str], out: bool = True) -> Iterable['InfoFlowStep']:
        """
        Generator which yields all information flows in/out of a
        specified source type.

        Parameters:
        source  The starting type.

        Keyword Parameters:
        out     If true, information flows out of the type will
                be returned.  If false, information flows in to the
                type will be returned.  Default is true.

        Yield: generator(steps)

        steps   A generator that returns the tuple of
                source, target, and rules for each
                information flow.
        """
        s = self.policy.lookup_type(type_)

        if self.rebuildsubgraph:
            self._build_subgraph()

        self.log.info("Generating all information flows {0} {1}".
                      format("out of" if out else "into", s))

        with suppress(NetworkXError):
            # NetworkXError: the type is valid but not in graph, e.g.
            # excluded or disconnected due to min weight

            if out:
                flows = self.subG.out_edges(s)
            else:
                flows = self.subG.in_edges(s)

            for source, target in flows:
                yield InfoFlowStep(self.subG, source, target)

    def get_stats(self) -> str:  # pragma: no cover
        """
        Get the information flow graph statistics.

        Return: str
        """
        if self.rebuildgraph:
            self._build_graph()

        return f"Graph nodes: {nx.number_of_nodes(self.G)}\n" \
               f"Graph edges: {nx.number_of_edges(self.G)}"

    #
    # Internal functions follow
    #

    def __generate_steps(self, path: List[Type]) -> InfoFlowPath:
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
        for s in range(1, len(path)):
            yield InfoFlowStep(self.subG, path[s - 1], path[s])

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
        self.G.name = "Information flow graph for {0}.".format(self.policy)

        self.perm_map.map_policy(self.policy)

        self.log.info("Building information flow graph from {0}...".format(self.policy))

        for rule in self.policy.terules():
            if rule.ruletype != TERuletype.allow:
                continue

            (rweight, wweight) = self.perm_map.rule_weight(cast(AVRule, rule))

            for s, t in itertools.product(rule.source.expand(), rule.target.expand()):
                # only add flows if they actually flow
                # in or out of the source type type
                if s != t:
                    if wweight:
                        edge = InfoFlowStep(self.G, s, t, create=True)
                        edge.rules.append(rule)
                        edge.weight = wweight

                    if rweight:
                        edge = InfoFlowStep(self.G, t, s, create=True)
                        edge.rules.append(rule)
                        edge.weight = rweight

        self.rebuildgraph = False
        self.rebuildsubgraph = True
        self.log.info("Completed building information flow graph.")
        self.log.debug("Graph stats: nodes: {0}, edges: {1}.".format(
            nx.number_of_nodes(self.G),
            nx.number_of_edges(self.G)))

    def _build_subgraph(self) -> None:
        if self.rebuildgraph:
            self._build_graph()

        self.log.info("Building information flow subgraph...")
        self.log.debug("Excluding {0!r}".format(self.exclude))
        self.log.debug("Min weight {0}".format(self.min_weight))
        self.log.debug("Exclude disabled conditional policy: {0}".format(
            self.booleans is not None))

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

                deleted_rules: List[AVRule] = []
                for rule in rule_list:
                    if rule not in deleted_rules:
                        edge.rules.remove(rule)
                        deleted_rules.append(rule)

                if not edge.rules:
                    delete_list.append(edge)

            self.subG.remove_edges_from(delete_list)

        self.rebuildsubgraph = False
        self.log.info("Completed building information flow subgraph.")
        self.log.debug("Subgraph stats: nodes: {0}, edges: {1}.".format(
            nx.number_of_nodes(self.subG),
            nx.number_of_edges(self.subG)))


class InfoFlowStep:

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

    rules = EdgeAttrList('rules')

    # use capacity to store the info flow weight so
    # we can use network flow algorithms naturally.
    # The weight for each edge is 1 since each info
    # flow step is no more costly than another
    # (see below add_edge() call)
    weight = EdgeAttrIntMax('capacity')

    def __init__(self, graph, source: Type, target: Type, create: bool = False) -> None:
        self.G = graph
        self.source = source
        self.target = target

        if not self.G.has_edge(source, target):
            if create:
                self.G.add_edge(source, target, weight=1)
                self.rules = None
                self.weight = None
            else:
                raise ValueError("InfoFlowStep does not exist in graph")

    def __getitem__(self, key):
        # This is implemented so this object can be used in NetworkX
        # functions that operate on (source, target) tuples
        if isinstance(key, slice):
            return [self._index_to_item(i) for i in range(* key.indices(2))]
        else:
            return self._index_to_item(key)

    def _index_to_item(self, index):
        """Return source or target based on index."""
        if index == 0:
            return self.source
        elif index == 1:
            return self.target
        else:
            raise IndexError("Invalid index (edges only have 2 items): {0}".format(index))
