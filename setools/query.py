# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from abc import ABC, abstractmethod
from logging import Logger
from typing import Iterable

from .policyrep import SELinuxPolicy


class PolicyQuery(ABC):

    """Abstract base class for SELinux policy queries."""

    log: Logger
    policy: SELinuxPolicy

    def __init__(self, policy: SELinuxPolicy, **kwargs) -> None:
        self.policy = policy

        # keys are sorted in reverse order so regex settings
        # are set before the criteria, e.g. name_regex
        # is set before name.  This ensures correct behavior
        # since the criteria descriptors are sensitve to
        # regex settings.
        for name in sorted(kwargs.keys(), reverse=True):
            attr = getattr(self, name, None)  # None is not callable
            if callable(attr):
                raise ValueError("Keyword parameter {0} conflicts with a callable.".format(name))

            setattr(self, name, kwargs[name])

    @abstractmethod
    def results(self) -> Iterable:
        """
        Generator which returns the matches for the query.  This method
        should be overridden by subclasses.
        """
        pass
