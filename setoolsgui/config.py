# Copyright 2019, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#

import os
import logging
import configparser
import threading
import typing

#
# Configfile constants
#
APOLCONFIG: typing.Final[str] = "~/.config/setools/apol.conf"
HELP_SECTION: typing.Final[str] = "Help"
HELP_PGM: typing.Final[str] = "assistant"
DEFAULT_HELP_PGM: typing.Final[str] = "/usr/bin/assistant"


class ApolConfig:

    """Apol configuration file."""

    def __init__(self) -> None:
        self.log: typing.Final = logging.getLogger(__name__)
        self._lock = threading.Lock()
        self.path: typing.Final = os.path.expanduser(APOLCONFIG)

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

    def save(self) -> None:
        """Save configuration file."""
        with self._lock:
            try:
                os.makedirs(os.path.dirname(self.path), mode=0o755, exist_ok=True)

                with open(self.path, "w") as fd:
                    self._config.write(fd)

            except Exception:
                self.log.critical(f"Failed to save configuration file \"{self.path}\"")
                self.log.debug("Backtrace", exc_info=True)

    @property
    def assistant(self) -> str:
        """Return the help program executable path."""
        with self._lock:
            return self._config.get(HELP_SECTION, HELP_PGM, fallback=DEFAULT_HELP_PGM)

    @assistant.setter
    def assistant(self, value: str) -> None:
        with self._lock:
            self._config.set(HELP_SECTION, HELP_PGM, value)
