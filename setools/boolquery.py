# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import logging
from typing import Iterable, Optional

from .descriptors import CriteriaDescriptor
from .mixins import MatchName
from .policyrep import Boolean
from .query import PolicyQuery


class BoolQuery(MatchName, PolicyQuery):

    """Query SELinux policy Booleans.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    name            The Boolean name to match.
    name_regex      If true, regular expression matching
                    will be used on the Boolean name.
    default         The default state to match.  If this
                    is None, the default state not be matched.
    """

    _default: Optional[bool] = None

    @property
    def default(self) -> Optional[bool]:
        return self._default

    @default.setter
    def default(self, value) -> None:
        if value is None:
            self._default = None
        else:
            self._default = bool(value)

    def __init__(self, policy, **kwargs) -> None:
        super(BoolQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self) -> Iterable[Boolean]:
        """Generator which yields all Booleans matching the criteria."""
        self.log.info("Generating Boolean results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self.log.debug("Default: {0.default}".format(self))

        for boolean in self.policy.bools():
            if not self._match_name(boolean):
                continue

            if self.default is not None and boolean.state != self.default:
                continue

            yield boolean
