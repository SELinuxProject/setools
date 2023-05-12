# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import pyqtSignal, QObject, QThread


class QueryResultsUpdater(QObject):

    """
    Thread for processing basic queries and updating result widgets.

    Parameters:
    query       The query object
    model       The model for the results

    Qt signals:
    finished    (int) The update has completed, with the number of results.
    raw_line    (str) A string to be appended to the raw results.
    """

    finished = pyqtSignal(int)
    raw_line = pyqtSignal(str)

    def __init__(self, query, model):
        super(QueryResultsUpdater, self).__init__()
        self.query = query
        self.model = model

    def update(self):
        """Run the query and update results."""
        self.model.beginResetModel()

        results = []
        counter = 0

        for counter, item in enumerate(self.query.results(), start=1):
            results.append(item)

            self.raw_line.emit(str(item))

            if QThread.currentThread().isInterruptionRequested():
                break
            elif not counter % 10:
                # yield execution every 10 rules
                QThread.yieldCurrentThread()

        self.model.resultlist = results
        self.model.endResetModel()

        self.finished.emit(counter)
