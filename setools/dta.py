# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#

import enum
import itertools
import logging
from collections import defaultdict
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass, InitVar
import typing

try:
    import networkx as nx
    from networkx.exception import NetworkXError, NetworkXNoPath, NodeNotFound

except ImportError as iex:
    logging.getLogger(__name__).debug(f"{iex.name} failed to import.")

from . import exception
from .descriptors import CriteriaDescriptor, EdgeAttrDict, EdgeAttrList
from .mixins import NetworkXGraphEdge
from .policyrep import AnyTERule, SELinuxPolicy, TERuletype, Type
from .query import DirectedGraphAnalysis

__all__ = ['DomainTransitionAnalysis',
           'DomainTransition',
           'DomainEntrypoint',
           'DTAPath']


@dataclass
class DomainEntrypoint:

    """Entrypoint list entry."""

    name: Type
    entrypoint: list[AnyTERule]
    execute: list[AnyTERule]
    type_transition: list[AnyTERule]

    def __lt__(self, other: "DomainEntrypoint") -> bool:
        # basic comparison for sorting
        return self.name < other.name

    def __str__(self) -> str:
        lines: list[str] = [f"\nEntrypoint {self.name}:",
                            "\tDomain entrypoint rule(s):"]
        lines.extend(f"\t{e}" for e in sorted(self.entrypoint))

        lines.append("\n\tFile execute rule(s):")
        lines.extend(f"\t{e}" for e in sorted(self.execute))

        if self.type_transition:
            lines.append("\n\tType transition rule(s):")
            lines.extend(f"\t{t}" for t in sorted(self.type_transition))

        return "\n".join(lines)


@dataclass
class DomainTransition:

    """Transition step output."""

    source: Type
    target: Type
    transition: list[AnyTERule]
    entrypoints: list[DomainEntrypoint]
    setexec: list[AnyTERule]
    dyntransition: list[AnyTERule]
    setcurrent: list[AnyTERule]

    def __format__(self, spec: str) -> str:
        lines: list[str] = [f"{self.source} -> {self.target}\n"]
        if spec == "full":
            if self.transition:
                lines.append("Domain transition rule(s):")
                lines.extend(str(t) for t in sorted(self.transition))

                if self.setexec:
                    lines.append("\nSet execution context rule(s):")
                    lines.extend(str(s) for s in sorted(self.setexec))

                lines.extend(f"{e}\n" for e in sorted(self.entrypoints))

            if self.dyntransition:
                lines.append("Dynamic transition rule(s):")
                lines.extend(str(d) for d in sorted(self.dyntransition))

                lines.append("\nSet current process context rule(s):")
                lines.extend(str(s) for s in sorted(self.setcurrent))

                lines.append("")

            return "\n".join(lines)

        if not spec:
            return lines[0]

        return super().__format__(spec)

    def __str__(self) -> str:
        return self.__format__("full")


#
# Typing
#
DTAPath = Iterable[DomainTransition]
RuleHash = defaultdict[Type, list[AnyTERule]]


class DomainTransitionAnalysis(DirectedGraphAnalysis):

    """
    Domain transition analysis.

    Parameters:
    policy      The policy to analyze.

    Keyword Parameters
    source      The source type of the analysis.
    target      The target type of the analysis.
    mode        The analysis mode (see DomainTransitionAnalysis.Mode)
    exclude     The types excluded from the domain transition analysis.
                (default is none)
    """

    class Mode(enum.Enum):

        """Domain transition analysis modes"""

        ShortestPaths = "All shortest paths"
        AllPaths = "All paths up to"  # N steps
        TransitionsOut = "Transitions out of the source domain."
        TransitionsIn = "Transitions into the target domain."

    DIRECT_MODES: typing.Final[tuple[Mode, ...]] = (Mode.TransitionsIn, Mode.TransitionsOut)
    TRANSITIVE_MODES: typing.Final[tuple[Mode, ...]] = (Mode.ShortestPaths, Mode.AllPaths)

    source = CriteriaDescriptor(lookup_function="lookup_type")
    target = CriteriaDescriptor(lookup_function="lookup_type")
    mode = Mode.ShortestPaths

    def __init__(self, policy: SELinuxPolicy, /, *,
                 reverse: bool = False,
                 source: Type | str | None = None,
                 target: Type | str | None = None,
                 mode: Mode = Mode.ShortestPaths,
                 depth_limit: int | None = 1,
                 exclude: Iterable[Type | str] | None = None) -> None:

        super().__init__(policy, reverse=reverse, source=source, target=target, mode=mode,
                         depth_limit=depth_limit, exclude=exclude)

        self._min_weight: int
        self._depth_limit: int | None

        self.rebuildgraph = True
        self.rebuildsubgraph = True

        try:
            self.G = nx.DiGraph()
            self.subG = self.G.copy()
        except NameError:
            self.log.critical("NetworkX is not available.  This is "
                              "requried for Domain Transition Analysis.")
            self.log.critical("This is typically in the python3-networkx package.")
            raise

    @property
    def depth_limit(self) -> int | None:
        return self._depth_limit

    @depth_limit.setter
    def depth_limit(self, value: int | None) -> None:
        if value is not None and value < 1:
            raise ValueError("Domain transition max depth must be positive.")

        self._depth_limit = value
        # no subgraph rebuild needed.

    @property
    def reverse(self) -> bool:
        return self._reverse

    @reverse.setter
    def reverse(self, direction) -> None:
        self._reverse = bool(direction)
        self.rebuildsubgraph = True

    @property
    def exclude(self) -> list[Type]:
        return self._exclude

    @exclude.setter
    def exclude(self, types: Iterable[Type | str] | None) -> None:
        if types:
            self._exclude = [self.policy.lookup_type(t) for t in types]
        else:
            self._exclude = []

        self.rebuildsubgraph = True

    def results(self) -> Iterable[DTAPath] | Iterable[DomainTransition]:
        if self.rebuildsubgraph:
            self._build_subgraph()

        self.log.info(f"Generating domain transition results from {self.policy}")
        self.log.debug(f"{self.source=}")
        self.log.debug(f"{self.target=}")
        self.log.debug(f"{self.mode=}, {self.depth_limit=}")

        with suppress(NetworkXNoPath, NodeNotFound, NetworkXError):
            match self.mode:
                case DomainTransitionAnalysis.Mode.ShortestPaths:
                    if not all((self.source, self.target)):
                        raise ValueError("Source and target types must be specified.")

                    self.log.info("Generating all shortest domain transition paths from "
                                  f"{self.source} to {self.target}...")

                    for path in nx.all_shortest_paths(self.subG,
                                                      self.source,
                                                      self.target):

                        yield self._generate_steps(path)

                case DomainTransitionAnalysis.Mode.AllPaths:
                    if not all((self.source, self.target)):
                        raise ValueError("Source and target types must be specified.")

                    self.log.info(f"Generating all domain transition paths from {self.source} "
                                  f"to {self.target}, max length {self.depth_limit}...")

                    for path in nx.all_simple_paths(self.subG,
                                                    self.source,
                                                    self.target,
                                                    cutoff=self.depth_limit):

                        yield self._generate_steps(path)

                case DomainTransitionAnalysis.Mode.TransitionsOut:
                    if not self.source:
                        raise ValueError("Source type must be specified.")

                    self.log.info(f"Generating all domain transitions out of {self.source}")
                    for source, target in nx.bfs_edges(self.subG, self.source,
                                                       depth_limit=self.depth_limit):
                        edge = Edge(self.subG, source, target)

                        yield DomainTransition(source,
                                               target,
                                               edge.transition,
                                               self._generate_entrypoints(edge),
                                               edge.setexec,
                                               edge.dyntransition,
                                               edge.setcurrent)

                case DomainTransitionAnalysis.Mode.TransitionsIn:
                    if not self.target:
                        raise ValueError("Target type must be specified.")

                    self.log.info(f"Generating all domain transitions into {self.target}")
                    # swap source and target since bfs_edges is reversed.
                    for target, source in nx.bfs_edges(self.subG, self.target, reverse=True,
                                                       depth_limit=self.depth_limit):
                        edge = Edge(self.subG, source, target)

                        yield DomainTransition(source,
                                               target,
                                               edge.transition,
                                               self._generate_entrypoints(edge),
                                               edge.setexec,
                                               edge.dyntransition,
                                               edge.setcurrent)

                case _:
                    raise ValueError(f"Unknown analysis mode: {self.mode}")

    def graphical_results(self) -> nx.DiGraph:

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

        self.log.info(f"Generating graphical domain transition results from {self.policy}")
        self.log.debug(f"{self.source=}")
        self.log.debug(f"{self.target=}")
        self.log.debug(f"{self.mode=}, {self.depth_limit=}")

        try:
            match self.mode:
                case DomainTransitionAnalysis.Mode.ShortestPaths:
                    if not all((self.source, self.target)):
                        raise ValueError("Source and target types must be specified.")

                    self.log.info("Generating graphical all shortest domain transition paths from "
                                  f"{self.source} to {self.target}...")
                    paths = nx.all_shortest_paths(self.subG, self.source, self.target)
                    edges = [pair for path in paths for pair in nx.utils.misc.pairwise(path)]

                    out = nx.DiGraph()
                    out.add_edges_from(edges)
                    return out

                case DomainTransitionAnalysis.Mode.AllPaths:
                    if not all((self.source, self.target)):
                        raise ValueError("Source and target types must be specified.")

                    self.log.info(f"Generating all domain transition paths from {self.source} "
                                  f"to {self.target}, max length {self.depth_limit}...")
                    paths = nx.all_simple_paths(self.subG, self.source, self.target,
                                                cutoff=self.depth_limit)
                    edges = [pair for path in paths for pair in nx.utils.misc.pairwise(path)]

                    out = nx.DiGraph()
                    out.add_edges_from(edges)
                    return out

                case DomainTransitionAnalysis.Mode.TransitionsOut:
                    if not self.source:
                        raise ValueError("Source type must be specified.")

                    self.log.info(f"Generating all domain transitions out of {self.source}.")
                    return nx.bfs_tree(self.subG, self.source, depth_limit=self.depth_limit)

                case DomainTransitionAnalysis.Mode.TransitionsIn:
                    if not self.target:
                        raise ValueError("Target type must be specified.")

                    self.log.info(f"Generating all domain transitions into {self.target}.")
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
        Get the domain transition graph statistics.

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
    @staticmethod
    def _generate_entrypoints(edge: 'Edge') -> list[DomainEntrypoint]:
        """
        Creates a list of entrypoint, execute, and
        type_transition rules for each entrypoint.

        Parameter:
        data     The dictionary of entrypoints.

        Return: list of tuple(type, entry, exec, trans)

        type     The entrypoint type.
        entry    The list of entrypoint rules.
        exec     The list of execute rules.
        trans    The list of type_transition rules.
        """
        return [DomainEntrypoint(e, edge.entrypoint[e], edge.execute[e], edge.type_transition[e])
                for e in edge.entrypoint]

    def _generate_steps(self, path: list[Type]) -> DTAPath:
        """
        Generator which yields the source, target, and associated rules
        for each domain transition.

        Parameter:
        path     A list of graph node names representing an information flow path.

        Yield: tuple(source, target, transition, entrypoints,
                     setexec, dyntransition, setcurrent)

        source          The source type for this step of the domain transition.
        target          The target type for this step of the domain transition.
        transition      The list of transition rules.
        entrypoints     Generator which yields entrypoint-related rules.
        setexec         The list of setexec rules.
        dyntranstion    The list of dynamic transition rules.
        setcurrent      The list of setcurrent rules.
        """

        for source, target in nx.utils.misc.pairwise(path):
            edge = Edge(self.subG, source, target)

            # Yield the actual source and target.
            # The above perspective is reversed
            # if the graph has been reversed.
            if self.reverse:
                real_source, real_target = target, source
            else:
                real_source, real_target = source, target

            yield DomainTransition(real_source, real_target,
                                   edge.transition,
                                   self._generate_entrypoints(edge),
                                   edge.setexec,
                                   edge.dyntransition,
                                   edge.setcurrent)

    #
    # Graph building functions
    #

    # Domain transition requirements:
    #
    # Standard transitions a->b:
    # allow a b:process transition;
    # allow a b_exec:file execute;
    # allow b b_exec:file entrypoint;
    #
    # and at least one of:
    # allow a self:process setexec;
    # type_transition a b_exec:process b;
    #
    # Dynamic transition x->y:
    # allow x y:process dyntransition;
    # allow x self:process setcurrent;
    #
    # Algorithm summary:
    # 1. iterate over all rules
    #   1. skip non allow/type_transition rules
    #   2. if process transition or dyntransition, create edge,
    #      initialize rule lists, add the (dyn)transition rule
    #   3. if process setexec or setcurrent, add to appropriate dict
    #      keyed on the subject
    #   4. if file exec, entrypoint, or type_transition:process,
    #      add to appropriate dict keyed on subject,object.
    # 2. Iterate over all graph edges:
    #   1. if there is a transition rule (else add to invalid
    #      transition list):
    #       1. use set intersection to find matching exec
    #          and entrypoint rules. If none, add to invalid
    #          transition list.
    #       2. for each valid entrypoint, add rules to the
    #          edge's lists if there is either a
    #          type_transition for it or the source process
    #          has setexec permissions.
    #       3. If there are neither type_transitions nor
    #          setexec permissions, add to the invalid
    #          transition list
    #   2. if there is a dyntransition rule (else add to invalid
    #      dyntrans list):
    #       1. If the source has a setcurrent rule, add it
    #          to the edge's list, else add to invalid
    #          dyntransition list.
    # 3. Iterate over all graph edges:
    #   1. if the edge has an invalid trans and dyntrans, delete
    #      the edge.
    #   2. if the edge has an invalid trans, clear the related
    #      lists on the edge.
    #   3. if the edge has an invalid dyntrans, clear the related
    #      lists on the edge.
    #
    def _build_graph(self) -> None:
        self.G.clear()
        self.G.name = f"Domain transition graph for {self.policy}."

        self.log.info(f"Building domain transition graph from {self.policy}...")

        # hash tables keyed on domain type
        setexec: RuleHash = defaultdict(list)
        setcurrent: RuleHash = defaultdict(list)

        # hash tables keyed on (domain, entrypoint file type)
        # the parameter for defaultdict has to be callable
        # hence the lambda for the nested defaultdict
        execute: defaultdict[Type, RuleHash] = defaultdict(lambda: defaultdict(list))
        entrypoint: defaultdict[Type, RuleHash] = defaultdict(lambda: defaultdict(list))

        # hash table keyed on (domain, entrypoint, target domain)
        type_trans: defaultdict[Type, defaultdict[Type, RuleHash]] = \
            defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

        for rule in self.policy.terules():
            if rule.ruletype == TERuletype.allow:
                if rule.tclass not in ["process", "file"]:
                    continue

                if rule.tclass == "process":
                    if "transition" in rule.perms:
                        for s, t in itertools.product(rule.source.expand(), rule.target.expand()):
                            # only add edges if they actually
                            # transition to a new type
                            if s != t:
                                edge = Edge(self.G, s, t, create=True)
                                edge.transition.append(rule)

                    if "dyntransition" in rule.perms:
                        for s, t in itertools.product(rule.source.expand(), rule.target.expand()):
                            # only add edges if they actually
                            # transition to a new type
                            if s != t:
                                e = Edge(self.G, s, t, create=True)
                                e.dyntransition.append(rule)

                    if "setexec" in rule.perms:
                        for s in rule.source.expand():
                            setexec[s].append(rule)

                    if "setcurrent" in rule.perms:
                        for s in rule.source.expand():
                            setcurrent[s].append(rule)

                else:
                    if "execute" in rule.perms:
                        for s, t in itertools.product(
                                rule.source.expand(),
                                rule.target.expand()):
                            execute[s][t].append(rule)

                    if "entrypoint" in rule.perms:
                        for s, t in itertools.product(rule.source.expand(), rule.target.expand()):
                            entrypoint[s][t].append(rule)

            elif rule.ruletype == TERuletype.type_transition:
                if rule.tclass != "process":
                    continue

                d = rule.default
                for s, t in itertools.product(rule.source.expand(), rule.target.expand()):
                    type_trans[s][t][d].append(rule)

        invalid_edge: list[Edge] = []
        clear_transition: list[Edge] = []
        clear_dyntransition: list[Edge] = []

        for s, t in self.G.edges():
            edge = Edge(self.G, s, t)
            invalid_trans = False
            invalid_dyntrans = False

            if edge.transition:
                # get matching domain exec w/entrypoint type
                entry = set(entrypoint[t].keys())
                exe = set(execute[s].keys())
                match = entry.intersection(exe)

                if not match:
                    # there are no valid entrypoints
                    invalid_trans = True
                else:
                    # TODO try to improve the
                    # efficiency in this loop
                    for m in match:
                        # pylint: disable=unsupported-assignment-operation
                        if s in setexec or type_trans[s][m]:
                            # add key for each entrypoint
                            edge.entrypoint[m] += entrypoint[t][m]
                            edge.execute[m] += execute[s][m]

                        if type_trans[s][m][t]:
                            edge.type_transition[m] += type_trans[s][m][t]

                    if s in setexec:
                        edge.setexec.extend(setexec[s])

                    if not edge.setexec and not edge.type_transition:
                        invalid_trans = True
            else:
                invalid_trans = True

            if edge.dyntransition:
                if s in setcurrent:
                    edge.setcurrent.extend(setcurrent[s])
                else:
                    invalid_dyntrans = True
            else:
                invalid_dyntrans = True

            # cannot change the edges while iterating over them,
            # so keep appropriate lists
            if invalid_trans and invalid_dyntrans:
                invalid_edge.append(edge)
            elif invalid_trans:
                clear_transition.append(edge)
            elif invalid_dyntrans:
                clear_dyntransition.append(edge)

        # Remove invalid transitions
        self.G.remove_edges_from(invalid_edge)
        for edge in clear_transition:
            # if only the regular transition is invalid,
            # clear the relevant lists
            del edge.transition
            del edge.execute
            del edge.entrypoint
            del edge.type_transition
            del edge.setexec
        for edge in clear_dyntransition:
            # if only the dynamic transition is invalid,
            # clear the relevant lists
            del edge.dyntransition
            del edge.setcurrent

        self.rebuildgraph = False
        self.rebuildsubgraph = True
        self.log.info("Completed building domain transition graph.")
        self.log.debug(
            f"Graph stats: nodes: {nx.number_of_nodes(self.G)}, "
            f"edges: {nx.number_of_edges(self.G)}.")

    def _remove_excluded_entrypoints(self) -> None:
        invalid_edges: list[Edge] = []
        for source, target in self.subG.edges():
            edge = Edge(self.subG, source, target)
            entrypoints = set(edge.entrypoint)
            entrypoints.intersection_update(self.exclude)

            if not entrypoints:
                # short circuit if there are no
                # excluded entrypoint types on
                # this edge.
                continue

            for e in entrypoints:
                # clear the entrypoint data
                # pylint: disable=unsupported-delete-operation
                del edge.entrypoint[e]
                del edge.execute[e]

                with suppress(KeyError):  # setexec
                    del edge.type_transition[e]

            # cannot delete the edges while iterating over them
            if not edge.entrypoint and not edge.dyntransition:
                invalid_edges.append(edge)

        self.subG.remove_edges_from(invalid_edges)

    def _build_subgraph(self) -> None:
        if self.rebuildgraph:
            self._build_graph()

        self.log.info("Building domain transition subgraph.")
        self.log.debug(f"{self.reverse=} {self.exclude=}")

        # reverse graph for reverse DTA
        if self.reverse:
            self.subG = self.G.reverse(copy=True)
        else:
            self.subG = self.G.copy()

        if self.exclude:
            # delete excluded domains from subgraph
            self.subG.remove_nodes_from(self.exclude)

            # delete excluded entrypoints from subgraph
            self._remove_excluded_entrypoints()

        self.rebuildsubgraph = False
        self.log.info("Completed building domain transition subgraph.")
        self.log.debug(
            f"Subgraph stats: nodes: {nx.number_of_nodes(self.subG)}, "
            f"edges: {nx.number_of_edges(self.subG)}.")


@dataclass
class Edge(NetworkXGraphEdge):

    """
    A graph edge.  Also used for returning domain transition steps.

    Parameters:
    graph       The NetworkX graph.
    source      The source type of the edge.
    target      The target tyep of the edge.

    Keyword Parameters:
    create      (T/F) create the edge if it does not exist.
                The default is False.
    """

    G: nx.DiGraph
    source: Type
    target: Type
    create: InitVar[bool] = False
    transition = EdgeAttrList()
    setexec = EdgeAttrList()
    dyntransition = EdgeAttrList()
    setcurrent = EdgeAttrList()
    entrypoint = EdgeAttrDict()
    execute = EdgeAttrDict()
    type_transition = EdgeAttrDict()

    def __post_init__(self, create) -> None:
        if not self.G.has_edge(self.source, self.target):
            if create:
                self.G.add_edge(self.source, self.target)
                self.transition = None
                self.entrypoint = None
                self.execute = None
                self.type_transition = None
                self.setexec = None
                self.dyntransition = None
                self.setcurrent = None
            else:
                raise ValueError("Edge does not exist in graph")
