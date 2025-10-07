# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from abc import ABC, abstractmethod
import logging
import typing

from . import exception

if typing.TYPE_CHECKING:
    from networkx import DiGraph
    from .policyrep import PolicyTarget, SELinuxPolicy


class PolicyQuery(ABC):

    """Abstract base class for all SELinux policy analyses."""

    # The platform required for this query, or None if any platform is allowed.
    required_platform: "PolicyTarget | None" = None

    _policy: "SELinuxPolicy"

    def __init__(self, policy: "SELinuxPolicy", **kwargs) -> None:
        self.policy: "SELinuxPolicy" = policy
        self.log: typing.Final = logging.getLogger(self.__module__)

        # keys are sorted in reverse order so regex settings
        # are set before the criteria, e.g. name_regex
        # is set before name.  This ensures correct behavior
        # since the criteria descriptors are sensitive to
        # regex settings.
        for name in sorted(kwargs.keys(), reverse=True):
            attr = getattr(self, name, None)  # None is not callable
            if callable(attr):
                raise ValueError(f"Keyword parameter {name} conflicts with a callable.")

            setattr(self, name, kwargs[name])

    @property
    def policy(self) -> "SELinuxPolicy":
        return self._policy

    @policy.setter
    def policy(self, value: "SELinuxPolicy") -> None:
        if self.required_platform and value.target_platform != self.required_platform:
            raise exception.PlatformMismatch(
                f"Policy {value} platform ({value.target_platform}) does not match required "
                f"platform {self.required_platform} for {self.__class__.__name__}")

        self._policy = value

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
