# Copyright 2019, Chris PeBenito <pebenito@ieee.org>
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

import os
import logging
import configparser
import threading

#
# Configfile constants
#
APOLCONFIG = "~/.config/setools/apol.conf"
HELP_SECTION = "Help"
HELP_PGM = "assistant"
DEFAULT_HELP_PGM = ("/usr/bin/assistant")


class ApolConfig:

    """Apol configuration file."""

    def __init__(self):
        self.log = logging.getLogger(__name__)
        self._lock = threading.Lock()
        self.path = os.path.expanduser(APOLCONFIG)

        self._config = configparser.ConfigParser()
        save = False

        if not self._config.read((self.path,)):
            save = True

        if not self._config.has_section(HELP_SECTION):
            self._config.add_section(HELP_SECTION)
            self._config.set(HELP_SECTION, HELP_PGM, DEFAULT_HELP_PGM)
            save = True

        if save:
            self.save()

    def save(self):
        """Save configuration file."""
        with self._lock:
            try:
                os.makedirs(os.path.dirname(self.path), mode=0o755, exist_ok=True)

                with open(self.path, "w") as fd:
                    self._config.write(fd)

            except Exception as ex:
                self.log.critical("Failed to save configuration file \"{0}\"".format(self.path))

    @property
    def assistant(self):
        with self._lock:
            return self._config.get(HELP_SECTION, HELP_PGM, fallback=DEFAULT_HELP_PGM)

    @assistant.setter
    def assistant(self, value):
        with self._lock:
            self._config.set(HELP_SECTION, HELP_PGM, value)
