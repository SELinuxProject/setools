# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from abc import ABC, abstractmethod
import logging
import typing

if typing.TYPE_CHECKING:
    from networkx import DiGraph
    from .policyrep import SELinuxPolicy


class PolicyQuery(ABC):

    """Abstract base class for all SELinux policy analyses."""

    def __init__(self, policy: "SELinuxPolicy", **kwargs) -> None:
        self.policy: "SELinuxPolicy" = policy
        self.log: typing.Final = logging.getLogger(self.__module__)

        # keys are sorted in reverse order so regex settings
        # are set before the criteria, e.g. name_regex
        # is set before name.  This ensures correct behavior
        # since the criteria descriptors are sensitve to
        # regex settings.
        for name in sorted(kwargs.keys(), reverse=True):
            attr = getattr(self, name, None)  # None is not callable
            if callable(attr):
                raise ValueError(f"Keyword parameter {name} conflicts with a callable.")

            setattr(self, name, kwargs[name])

    @abstractmethod
    def results(self) -> typing.Iterable:
        """
        Generator which returns the matches for the query.  This method
        should be overridden by subclasses.
        """


class DirectedGraphAnalysis(PolicyQuery):

    """Abstract base class for graph-basded SELinux policy analysis."""

    G: "DiGraph"

    @abstractmethod
    def graphical_results(self) -> "DiGraph":
        """Return the results of the analysis as a NetworkX directed graph."""
