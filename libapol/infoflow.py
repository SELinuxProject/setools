# Copyright 2014, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
import itertools

import policyrep
import permmap
import networkx as nx


class InfoFlowAnalysis(object):

    """Information flow analysis."""

    def __init__(self, policy, perm_map, minweight=1, exclude=[]):
        """
        Parameters:
        policy      The policy to analyze.
        perm_map    The permission map or path to the permission map file.
        minweight	The minimum permission weight to include in the analysis.
                    (default is 1)
        exclude     The types excluded from the information flow analysis.
                    (default is none)
        """

        self.policy = policy

        self.set_min_weight(minweight)
        self.set_perm_map(perm_map)
        self.set_exclude(exclude)
        self.rebuildgraph = True

        self.G = nx.DiGraph()

    def set_min_weight(self, w):
        """
        Set the minimum permission weight for the information flow analysis.

        Parameter:
        w           Minimum permission weight (1-10)

        Exceptions:
        ValueError  The minimum weight is not 1-10.
        """
        if not 1 <= w <= 10:
            raise ValueError(
                "Min information flow weight must be an integer 1-10.")

        self.minweight = w
        self.rebuildgraph = True

    def set_perm_map(self, perm_map):
        """
        Set the permission map used for the information flow analysis.

        Parameter:
        perm_map    The permission map or path to the permission map file.

        Exceptions:
        TypeError   The map is not a file path or permission map object.
        """
        if not isinstance(perm_map, (str, permmap.PermissionMap)):
            raise TypeError(
                "Permission map must be a permission map object or a path to a permission map file.")

        if isinstance(perm_map, str):
            self.perm_map = permmap.PermissionMap(perm_map)
        else:
            self.perm_map = perm_map

        self.rebuildgraph = True

    def set_exclude(self, exclude):
        """
        Set the types to exclude from the information flow analysis.

        Parameter:
        exclude         A list of types.
        """

        # TODO: a list comprehension that turns the strings into
        # Type objects
        self.exclude = exclude

    def __get_steps(self, path):
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
            source = path[s - 1]
            target = path[s]
            yield source, target, self.G.edge[source][target]['rules']

    def shortest_path(self, source, target):
        """
        Generator which yields one shortest path between the source
        and target types (there may be more).

        Parameters:
        source   The source type.
        target   The target type.

        Yield: generator(steps)

        steps Yield: tuple(source, target, rules)

        source	 The source type for this step of the information flow.
        target   The target type for this step of the information flow.
        rules    The list of rules creating this information flow step.
        """
        if self.rebuildgraph:
            self._build_graph()

        if source in self.G and target in self.G:
            try:
                path = nx.shortest_path(self.G, source, target)
            except nx.exception.NetworkXNoPath:
                pass
            else:
                # written as a generator so the caller code
                # works the same way independent of the graph alg
                yield self.__get_steps(path)

    def all_paths(self, source, target, maxlen=2):
        """
        Generator which yields all paths between the source and target
        up to the specified maximum path length.  This algorithm
        tends to get very expensive above 3-5 steps, depending
        on the policy complexity.

        Parameters:
        source	  The source type.
        target    The target type.
        maxlen    Maximum length of paths.

        Yield: generator(steps)

        steps Yield: tuple(source, target, rules)

        source    The source type for this step of the information flow.
        target    The target type for this step of the information flow.
        rules     The list of rules creating this information flow step.
        """
        if self.rebuildgraph:
            self._build_graph()

        if source in self.G and target in self.G:
            try:
                paths = nx.all_simple_paths(self.G, source, target, maxlen)
            except nx.exception.NetworkXNoPath:
                pass
            else:
                for p in paths:
                    yield self.__get_steps(p)

    def all_shortest_paths(self, source, target):
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
        if self.rebuildgraph:
            self._build_graph()

        if source in self.G and target in self.G:
            try:
                paths = nx.all_shortest_paths(self.G, source, target)
            except nx.exception.NetworkXNoPath:
                pass
            else:
                for p in paths:
                    yield self.__get_steps(p)

    def infoflows(self, source):
        """
        Generator which yields all information flows out of a
        specified source type.

        Parameters:
        source  The starting type.

        Yield: generator(steps)

        steps   A generator that returns the tuple of
                source, target, and rules for each
                information flow.
        """
        if self.rebuildgraph:
            self._build_graph()

        for source, target, data in self.G.out_edges_iter(source, data=True):
            yield source, target, data["rules"]

    def get_stats(self):
        """
        Get the information flow graph statistics.

        Return:	tuple(nodes, edges)

        nodes    The number of nodes (types) in the graph.
        edges    The number of edges (information flows between types)
                 in the graph.
        """
        return (self.G.number_of_nodes(), self.G.number_of_edges())

    #
    #
    # (Internal) Graph building functions
    #
    #
    # 1. __build_graph determines the flow in each direction for each TE
    #    rule and then expands the rule (ignoring excluded types)
    # 2. __add_flow Simply creates edges in the appropriate direction.
    #    (decrease chance of coding errors for graph operations)
    # 3. __add_edge does the actual graph insertions.  Nodes are implictly
    #    created by the edge additions, i.e. types that have no info flow
    #    due to permission weights or are excluded do not appear in the graph.
    def __add_edge(self, source, target, rule, weight):
        # use capacity to store the info flow weight so
        # we can use network flow algorithms naturally.
        # The weight for each edge is 1 since each info
        # flow step is no more costly than another
        if self.G.has_edge(source, target):
            self.G.edge[source][target]['rules'].append(rule)
            edgecap = self.G.edge[source][target]['capacity']
            self.G.edge[source][target]['capacity'] = max(edgecap, weight)
        else:
            self.G.add_edge(
                source, target, capacity=weight, weight=1, rules=[rule])

    def __add_flow(self, source, target, rule, ww, rw):
        assert max(ww, rw) >= self.minweight

        # only add flows if they actually flow
        # in our out of the source type type
        if source != target:
            if ww >= self.minweight:
                self.__add_edge(source, target, rule, ww)

            if rw >= self.minweight:
                self.__add_edge(target, source, rule, rw)

    def _build_graph(self):
        self.G.clear()

        for r in self.policy.terules():
            if r.ruletype != "allow":
                continue

            (rweight, wweight) = self.perm_map.rule_weight(r)

            # 1. only proceed if weight meets or exceeds the minimum weight
            # 2. expand source and target to handle attributes
            # 3. ignore flow if one of the types is in the exclude list
            if max(rweight, wweight) >= self.minweight:
                for s, t in itertools.product(r.source.expand(), r.target.expand()):
                    if s not in self.exclude and t not in self.exclude:
                        self.__add_flow(str(s), str(t), r, wweight, rweight)

        self.rebuildgraph = False
