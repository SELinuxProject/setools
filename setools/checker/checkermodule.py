# Copyright 2020, Microsoft Corporation
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

import sys
import logging
from abc import ABC, abstractmethod

from .globalkeys import CHECK_TYPE_KEY, CHECK_DESC_KEY, CHECK_DISABLE, GLOBAL_CONFIG_KEYS
from ..exception import InvalidCheckOption


__all__ = ['CheckerModule']


class CheckerModule(ABC):

    """Abstract base class for policy checker modules."""

    # The name of the check used in config files.
    # This must be set by subclasses.
    check_type = None

    # The container of valid config keys specific to the check
    # This is in addition to the common config keys
    # in the GLOBAL_CONFIG_KEYS above.  This must be set by subclasses.
    # If no additional keys  are needed, this should be set to an
    # empty container.
    check_config = None

    # T/F log findings that pass the check.
    log_passing = False

    # Default output to stdout.
    output = sys.stdout

    def __init__(self, policy, checkname, config):
        if self.check_type is None:
            raise NotImplementedError("Checker module does not set a check_type.")

        if self.check_config is None:
            raise NotImplementedError("Checker module does not set a valid key list.")

        self.policy = policy
        self.checkname = checkname

        # ensure there is a logger available. This should
        # be replaced with the concrete class' logger
        self.log = logging.getLogger(__name__)

        # Check available options are valid
        valid_options = GLOBAL_CONFIG_KEYS | self.check_config
        for k in config:
            if k not in valid_options:
                raise InvalidCheckOption("{}: Invalid option: {}".format(
                    self.checkname, k))

        # Make sure all global config attrs are initialized for this check
        self.desc = config.get(CHECK_DESC_KEY)
        self.disable = config.get(CHECK_DISABLE)

    def log_info(self, msg):
        """Output an informational message."""
        self.output.write(msg)
        self.output.write("\n")
        self.log.debug(msg)

    def log_ok(self, msg):
        """
        Log findings that pass the check.  By default these messages are
        surpressed unless self.log_passing is True.
        """
        if self.log_passing:
            self.output.write("P   * {}\n".format(msg))
        self.log.debug("P   * {}".format(msg))

    def log_fail(self, msg):
        """Log findings that fail the check."""
        self.output.write("{}   * {}\n".format("F" if self.log_passing else " ", msg))
        self.log.debug("F   * {}".format(msg))

    @abstractmethod
    def run(self):
        """
        Run the configured check on the policy.

        Return:   List of failed items in the check.  If the check passes, list is empty.
        """
        pass
