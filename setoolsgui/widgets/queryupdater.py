# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import logging
import typing

from PyQt5 import QtCore
import setools

from . import models

Q = typing.TypeVar("Q", bound=setools.PolicyQuery)

# The first parameter is the result counter and second parameter
# is a single result to render.
RenderFunction = typing.Callable[[int, typing.Any], str]


class QueryResultsUpdater(QtCore.QObject, typing.Generic[Q]):

    """
    Thread for processing basic queries and updating result widgets.

    Parameters:
    query       The query object
    model       The model for the results

    Keyword Parameters:
    render      A two parameter function that renders each item returned
                from the query to a string.  This is added to the raw output
                widgets.  The default is equivalent to str().

    Qt signals:
    failed      (str) The updated failed, with an error message.
    finished    (int) The update has completed, with the number of results.
    raw_line    (str) A string to be appended to the raw results.
    """

    failed = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal(int)
    raw_line = QtCore.pyqtSignal(str)

    def __init__(self, query: Q,
                 model: models.SEToolsTableModel | None = None,
                 render: RenderFunction = lambda _, x: str(x),
                 result_limit: int = 0) -> None:

        super().__init__()
        self.log: typing.Final = logging.getLogger(query.__module__)
        self.query: typing.Final[Q] = query
        self.model = model
        self.render = render
        self.result_limit = result_limit

    def update(self) -> None:
        """Run the query and update results."""
        results: typing.List = []
        counter = 0

        try:
            for counter, item in enumerate(self.query.results(), start=1):
                results.append(item)

                self.raw_line.emit(self.render(counter, item))

                this_thread = QtCore.QThread.currentThread()
                # type narrowing:
                assert this_thread, "Unable to get curre thread, this is an SETools bug"
                if this_thread.isInterruptionRequested():
                    break

                if counter % 10 == 0:
                    # yield execution every 10 rules
                    QtCore.QThread.yieldCurrentThread()

                if counter % 1000 == 0:
                    self.log.info(f"Generated {counter} results so far.")

                if self.result_limit and counter >= self.result_limit:
                    break

            self.log.info(f"Generated {counter} total results.")

            if self.model:
                self.model.item_list = results
            self.finished.emit(counter)

        except Exception as e:
            msg = f"Unexpected exception during processing: {e}"
            self.failed.emit(msg)
            self.log.exception(msg)
