# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import logging
from typing import TYPE_CHECKING

from PyQt5 import QtCore

if TYPE_CHECKING:
    from setools.query import PolicyQuery
    from .models.table import SEToolsTableModel


class QueryResultsUpdater(QtCore.QObject):

    """
    Thread for processing basic queries and updating result widgets.

    Parameters:
    query       The query object
    model       The model for the results

    Qt signals:
    finished    (int) The update has completed, with the number of results.
    raw_line    (str) A string to be appended to the raw results.
    """

    finished = QtCore.pyqtSignal(int)
    raw_line = QtCore.pyqtSignal(str)

    def __init__(self, query: "PolicyQuery", model: "SEToolsTableModel") -> None:
        super().__init__()
        self.query = query
        self.model = model
        self.log = logging.getLogger(self.query.__module__)

    def update(self) -> None:
        """Run the query and update results."""
        results = []
        counter = 0

        for counter, item in enumerate(self.query.results(), start=1):
            results.append(item)

            self.raw_line.emit(str(item))

            if QtCore.QThread.currentThread().isInterruptionRequested():
                break
            elif counter % 10 == 0:
                # yield execution every 10 rules
                QtCore.QThread.yieldCurrentThread()

            if counter % 100 == 0:
                self.log.info(f"Generated {counter} results so far.")

        self.log.info(f"Generated {counter} total results.")
        self.model.item_list = results

        self.finished.emit(counter)
