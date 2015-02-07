# Copyright 2014-2015, Tresys Technology, LLC
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
from collections import defaultdict

import networkx as nx


class DomainTransitionAnalysis(object):

    """Domain transition analysis."""

    def __init__(self, policy, reverse=False, exclude=[]):
        """
        Parameter:
        policy   The policy to analyze.
        """
        self.policy = policy
        self.set_exclude(exclude)
        self.set_reverse(reverse)
        self.rebuildgraph = True
        self.rebuildsubgraph = True
        self.G = nx.DiGraph()

    def __get_entrypoints(self, source, target):
        """
        Generator which returns the entrypoint, execute, and
        type_transition rules for each entrypoint.

        Parameter:
        source   The source node for the transition.
        target   The target node for the transition.

        Yield: tuple(type, entry, exec, trans)

        type     The entrypoint type.
        entry    The entrypoint rules.
        exec     The execute rules.
        trans    The type_transition rules.
        """
        for e in self.subG.edge[source][target]['entrypoint']:
            if self.subG.edge[source][target]['type_transition'][e]:
                yield e, \
                    self.subG.edge[source][target]['entrypoint'][e], \
                    self.subG.edge[source][target]['execute'][e], \
                    self.subG.edge[source][target]['type_transition'][e]
            else:
                yield e, \
                    self.subG.edge[source][target]['entrypoint'][e], \
                    self.subG.edge[source][target]['execute'][e], \
                    []

    def __get_steps(self, path):
        """
        Generator which returns the source, target, and associated rules
        for each domain transition.

        Parameter:
        path     A list of graph node names representing an information flow path.

        Yield: tuple(source, target, transition, entrypoints,
                     setexec, dyntransition, setcurrent)

        source          The source type for this step of the domain transition.
        target          The target type for this step of the domain transition.
        transition      The list of TE rules providing transition permissions.
        entrypoints     Generator which provides entrypoint-related rules.
        setexec         The list of setexec rules.
        dyntranstion    The list of dynamic transition rules.
        setcurrent      The list of setcurrent rules.
        """

        for s in range(1, len(path)):
            source = path[s - 1]
            target = path[s]

            if self.reverse:
                real_source, real_target = target, source
            else:
                real_source, real_target = source, target

            # It seems that NetworkX does not reverse the dictionaries
            # that store the attributes, so real_* is used everywhere
            # below, rather than just the first line.
            yield real_source, real_target, \
                self.subG.edge[real_source][real_target]['transition'], \
                self.__get_entrypoints(real_source, real_target), \
                self.subG.edge[real_source][real_target]['setexec'], \
                self.subG.edge[real_source][real_target]['dyntransition'], \
                self.subG.edge[real_source][real_target]['setcurrent']

    def set_reverse(self, reverse):
        """
        Set forward/reverse DTA direction.

        Parameter:
        reverse     If true, a reverse DTA is performed, otherwise a
                    forward DTA is performed.
        """

        self.reverse = bool(reverse)
        self.rebuildsubgraph = True

    def set_exclude(self, exclude):
        """
        Set the domains to exclude from the domain transition analysis.

        Parameter:
        exclude         A list of types.
        """

        self.exclude = [self.policy.lookup_type(t) for t in exclude]
        self.rebuildsubgraph = True

    def shortest_path(self, source, target):
        """
        Generator which yields one shortest domain transition path
        between the source and target types (there may be more).

        Parameters:
        source  The source type.
        target  The target type.

        Yield: generator(steps)

        steps   A generator that returns the tuple of
                source, target, and rules for each
                domain transition.
        """
        s = self.policy.lookup_type(source)
        t = self.policy.lookup_type(target)

        if self.rebuildsubgraph:
            self._build_subgraph()

        if s in self.subG and t in self.subG:
            try:
                path = nx.shortest_path(self.subG, s, t)
            except nx.exception.NetworkXNoPath:
                pass
            else:
                yield self.__get_steps(path)

    def all_paths(self, source, target, maxlen=2):
        """
        Generator which yields all domain transition paths between
        the source and target up to the specified maximum path
        length.

        Parameters:
        source   The source type.
        target   The target type.
        maxlen   Maximum length of paths.

        Yield: generator(steps)

        steps    A generator that returns the tuple of
                 source, target, and rules for each
                 domain transition.
        """
        s = self.policy.lookup_type(source)
        t = self.policy.lookup_type(target)

        if self.rebuildsubgraph:
            self._build_subgraph()

        if s in self.subG and t in self.subG:
            try:
                paths = nx.all_simple_paths(self.subG, s, t, maxlen)
            except nx.exception.NetworkXNoPath:
                pass
            else:
                for p in paths:
                    yield self.__get_steps(p)

    def all_shortest_paths(self, source, target):
        """
        Generator which yields all shortest domain transition paths
        between the source and target types.

        Parameters:
        source   The source type.
        target   The target type.

        Yield: generator(steps)

        steps    A generator that returns the tuple of
                 source, target, and rules for each
                 domain transition.
        """
        s = self.policy.lookup_type(source)
        t = self.policy.lookup_type(target)

        if self.rebuildsubgraph:
            self._build_subgraph()

        if s in self.subG and t in self.subG:
            try:
                paths = nx.all_shortest_paths(self.subG, s, t)
            except nx.exception.NetworkXNoPath:
                pass
            else:
                for p in paths:
                    yield self.__get_steps(p)

    def transitions(self, type_):
        """
        Generator which yields all domain transitions out of a
        specified source type.

        Parameters:
        type_   The starting type.

        Yield: generator(steps)

        steps   A generator that returns the tuple of
                source, target, and rules for each
                domain transition.
        """
        s = self.policy.lookup_type(type_)

        if self.rebuildsubgraph:
            self._build_subgraph()

        for source, target in self.subG.out_edges_iter(s):
            if self.reverse:
                real_source, real_target = target, source
            else:
                real_source, real_target = source, target

            # It seems that NetworkX does not reverse the dictionaries
            # that store the attributes, so real_* is used everywhere
            # below, rather than just the first line.
            yield real_source, real_target, \
                self.subG.edge[real_source][real_target]['transition'], \
                self.__get_entrypoints(real_source, real_target), \
                self.subG.edge[real_source][real_target]['setexec'], \
                self.subG.edge[real_source][real_target]['dyntransition'], \
                self.subG.edge[real_source][real_target]['setcurrent']

    def get_stats(self):
        """
        Get the domain transition graph statistics.

        Return:	tuple(nodes, edges)

        nodes    The number of nodes (types) in the graph.
        edges    The number of edges (domain transitions) in the graph.
        """
        return (self.G.number_of_nodes(), self.G.number_of_edges())

    # Graph edge properties:
    # Each entry in the property dict corresponds to
    # a rule list.  For entrypoint/execute/type_transition
    # it is a dictionary keyed on the entrypoint type.
    def __add_edge(self, source, target):
        self.G.add_edge(source, target)
        if not 'transition' in self.G[source][target]:
            self.G[source][target]['transition'] = []
        if not 'entrypoint' in self.G[source][target]:
            self.G[source][target]['entrypoint'] = defaultdict(list)
        if not 'execute' in self.G[source][target]:
            self.G[source][target]['execute'] = defaultdict(list)
        if not 'type_transition'in self.G[source][target]:
            self.G[source][target]['type_transition'] = defaultdict(list)
        if not 'setexec' in self.G[source][target]:
            self.G[source][target]['setexec'] = []
        if not 'dyntransition' in self.G[source][target]:
            self.G[source][target]['dyntransition'] = []
        if not 'setcurrent' in self.G[source][target]:
            self.G[source][target]['setcurrent'] = []

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
    #	1. skip non allow/type_transition rules
    #	2. if process transition or dyntransition, create edge,
    #	   initialize rule lists, add the (dyn)transition rule
    #	3. if process setexec or setcurrent, add to appropriate dict
    #	   keyed on the subject
    #	4. if file exec, entrypoint, or type_transition:process,
    #	   add to appropriate dict keyed on subject,object.
    # 2. Iterate over all graph edges:
    #	1. if there is a transition rule (else add to invalid
    #	   transition list):
    #		1. use set intersection to find matching exec
    #		   and entrypoint rules. If none, add to invalid
    #		   transition list.
    #		2. for each valid entrypoint, add rules to the
    #		   edge's lists if there is either a
    #		   type_transition for it or the source process
    #		   has setexec permissions.
    #		3. If there are neither type_transitions nor
    #		   setexec permissions, add to the invalid
    #		   transition list
    #	2. if there is a dyntransition rule (else add to invalid
    #	   dyntrans list):
    #		1. If the source has a setcurrent rule, add it
    #		   to the edge's list, else add to invalid
    #		   dyntransition list.
    # 3. Iterate over all graph edges:
    #	1. if the edge has an invalid trans and dyntrans, delete
    #	   the edge.
    #	2. if the edge has an invalid trans, clear the related
    #	   lists on the edge.
    #	3. if the edge has an invalid dyntrans, clear the related
    #	   lists on the edge.
    #
    def _build_graph(self):
        self.G.clear()

        # hash tables keyed on domain type
        setexec = defaultdict(list)
        setcurrent = defaultdict(list)

        # hash tables keyed on (domain, entrypoint file type)
        # the parameter for defaultdict has to be callable
        # hence the lambda for the nested defaultdict
        execute = defaultdict(lambda: defaultdict(list))
        entrypoint = defaultdict(lambda: defaultdict(list))

        # hash table keyed on (domain, entrypoint, target domain)
        type_trans = defaultdict(
            lambda: defaultdict(lambda: defaultdict(list)))

        for r in self.policy.terules():
            if r.ruletype == "allow":
                if r.tclass not in ["process", "file"]:
                    continue

                perms = r.perms

                if r.tclass == "process":
                    if "transition" in perms:
                        for s, t in itertools.product(
                                r.source.expand(),
                                r.target.expand()):
                            self.__add_edge(s, t)
                            self.G[s][t]['transition'].append(r)

                    if "dyntransition" in perms:
                        for s, t in itertools.product(
                                r.source.expand(),
                                r.target.expand()):
                            self.__add_edge(s, t)
                            self.G[s][t]['dyntransition'].append(r)

                    if "setexec" in perms:
                        for s in r.source.expand():
                            setexec[s].append(r)

                    if "setcurrent" in perms:
                        for s in r.source.expand():
                            setcurrent[s].append(r)

                else:
                    if "execute" in perms:
                        for s, t in itertools.product(
                                r.source.expand(),
                                r.target.expand()):
                            execute[s][t].append(r)

                    if "entrypoint" in perms:
                        for s, t in itertools.product(
                                r.source.expand(),
                                r.target.expand()):
                            entrypoint[s][t].append(r)

            elif r.ruletype == "type_transition":
                if r.tclass != "process":
                    continue

                d = r.default
                for s, t in itertools.product(
                        r.source.expand(),
                        r.target.expand()):
                    type_trans[s][t][d].append(r)

        invalid_edge = []
        clear_transition = []
        clear_dyntransition = []

        for s, t in self.G.edges_iter():
            invalid_trans = False
            invalid_dyntrans = False

            if self.G[s][t]['transition']:
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
                        if s in setexec or type_trans[s][m]:
                            # add subkey for each entrypoint
                            self.G[s][t]['entrypoint'][m] += entrypoint[t][m]
                            self.G[s][t]['execute'][m] += execute[s][m]

                        if type_trans[s][m][t]:
                            self.G[s][t]['type_transition'][
                                m] += type_trans[s][m][t]

                    if s in setexec:
                        self.G[s][t]['setexec'] += setexec[s]

                    if not self.G[s][t]['setexec'] and not self.G[s][t]['type_transition']:
                        invalid_trans = True
            else:
                invalid_trans = True

            if self.G[s][t]['dyntransition']:
                if s in setcurrent:
                    self.G[s][t]['setcurrent'] += setcurrent[s]
                else:
                    invalid_dyntrans = True
            else:
                invalid_dyntrans = True

            # cannot change the edges while iterating over them,
            # so keep appropriate lists
            if invalid_trans and invalid_dyntrans:
                invalid_edge.append((s, t))
            elif invalid_trans:
                clear_transition.append((s, t))
            elif invalid_dyntrans:
                clear_dyntransition.append((s, t))

        # Remove invalid transitions
        self.G.remove_edges_from(invalid_edge)
        for s, t in clear_transition:
            # if only the regular transition is invalid,
            # clear the relevant lists
            del self.G[s][t]['transition'][:]
            self.G[s][t]['execute'].clear()
            self.G[s][t]['entrypoint'].clear()
            self.G[s][t]['type_transition'].clear()
            del self.G[s][t]['setexec'][:]
        for s, t in clear_dyntransition:
            # if only the dynamic transition is invalid,
            # clear the relevant lists
            del self.G[s][t]['dyntransition'][:]
            del self.G[s][t]['setcurrent'][:]

        self.rebuildgraph = False
        self.rebuildsubgraph = True

    def _build_subgraph(self):
        if self.rebuildgraph:
            self._build_graph()

        # delete excluded domains from subgraph
        nodes = [n for n in self.G.nodes() if n not in self.exclude]
        # subgraph created this way to get copies of the edge
        # attributes. otherwise the edge attributes point to the
        # original graph, and the entrypoint removal below would also
        # affect the main graph.
        self.subG = nx.DiGraph(self.G.subgraph(nodes))

        # delete excluded entrypoints from subgraph
        invalid_edge = []
        for source, target in self.subG.edges_iter():
            # can't change a dictionary that you're iterating over
            entrypoints = list(self.subG.edge[source][target]['entrypoint'])

            for e in entrypoints:
                # clear the entrypoint data
                if e in self.exclude:
                    del self.subG.edge[source][target]['entrypoint'][e]
                    del self.subG.edge[source][target]['execute'][e]

                    try:
                        del self.subG.edge[source][
                            target]['type_transition'][e]
                    except KeyError:  # setexec
                        pass

                # cannot change the edges while iterating over them
                if len(self.subG.edge[source][target]['entrypoint']) == 0 and len(self.subG.edge[source][target]['dyntransition']) == 0:
                    invalid_edge.append((source, target))

        self.subG.remove_edges_from(invalid_edge)

        # reverse graph for reverse DTA
        if self.reverse:
            self.subG.reverse(copy=False)

        self.rebuildsubgraph = False
