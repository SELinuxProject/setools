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
    failed      (str) The updated failed, with an error message.
    finished    (int) The update has completed, with the number of results.
    raw_line    (str) A string to be appended to the raw results.
    """

    failed = QtCore.pyqtSignal(str)
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

        try:
            for counter, item in enumerate(self.query.results(), start=1):
                results.append(item)

                self.raw_line.emit(str(item))

                if QtCore.QThread.currentThread().isInterruptionRequested():
                    break
                elif counter % 10 == 0:
                    # yield execution every 10 rules
                    QtCore.QThread.yieldCurrentThread()

                if counter % 1000 == 0:
                    self.log.info(f"Generated {counter} results so far.")

            self.log.info(f"Generated {counter} total results.")

        except Exception as e:
            self.failed.emit(str(e))

        else:
            self.model.item_list = results
            self.finished.emit(counter)
