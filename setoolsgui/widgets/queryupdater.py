# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import logging
import typing

import networkx as nx
from PyQt6 import QtCore, QtGui, QtWidgets
import setools

from . import models

Q = typing.TypeVar("Q", bound=setools.PolicyQuery)
R = typing.TypeVar("R")  # type of result from query

# The first parameter is the result counter and second parameter
# is a single result to render.
RenderFunction = typing.Callable[[int, typing.Any], str]


class QueryResultsUpdater(QtCore.QObject, typing.Generic[Q, R]):

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

    def __init__(self, query: Q, /, *,
                 table_model: models.SEToolsTableModel | None = None,
                 graphics_buffer: QtWidgets.QLabel | None = None,
                 render: RenderFunction = lambda _, x: str(x),
                 result_limit: int = 0) -> None:

        super().__init__()
        self.log: typing.Final = logging.getLogger(query.__module__)
        self.query: typing.Final[Q] = query
        self.table_model = table_model
        self.render = render
        self.result_limit = result_limit
        self.graphics_buffer = graphics_buffer

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

            if self.table_model:
                self.log.info("Updating results in table model.")
                self.table_model.item_list = results

            if self.graphics_buffer:
                assert isinstance(self.query, setools.query.DirectedGraphAnalysis)
                self.log.info("Generating graphical results.")
                self.graphics_buffer.clear()
                pgv = nx.nx_agraph.to_agraph(self.query.graphical_results())
                pic = QtGui.QPixmap()
                pic.loadFromData(pgv.draw(prog="dot", format="png"), "PNG")
                self.graphics_buffer.setPixmap(pic)

            self.finished.emit(counter)

        except Exception as e:
            msg = f"Unexpected exception during processing: {e}"
            self.log.exception(msg)
            self.failed.emit(msg)


A = typing.TypeVar("A", bound=setools.query.DirectedGraphAnalysis)
N = typing.TypeVar("N")  # type of object for browser (graph node)
ChildData = tuple[N, R]
ChildrenData = list[ChildData]
BrowserRenderFunction = typing.Callable[[A, R], ChildData]


class BrowserUpdater(QtCore.QObject, typing.Generic[A, R, N]):

    """Thread for processing additional analysis for the browser."""

    failed = QtCore.pyqtSignal(str)
    result = QtCore.pyqtSignal(list)

    query: A
    render: BrowserRenderFunction

    def run(self) -> None:
        try:
            assert hasattr(self, "query"), "query attribute not set, this is an SETools bug"
            assert hasattr(self, "render"), "render attribute not set, this is an SETools bug"
            log = logging.getLogger(self.query.__module__)
            log.debug(f"Starting browser update for {self.query=}")

            this_thread = QtCore.QThread.currentThread()
            # type narrowing:
            assert this_thread, "Unable to get current thread, this is an SETools bug"

            count: int = 0
            child: list[R]
            children: ChildrenData = []
            for count, child in enumerate(self.query.results(), start=1):
                # Generate results for flow browser
                children.append(self.render(self.query, child))

                if this_thread.isInterruptionRequested():
                    break

                if count % 10 == 0:
                    # yield execution every 10 rules
                    this_thread.yieldCurrentThread()

            self.result.emit(children)
            log.debug(f"Generated {count} total results for browser.")

        except Exception as e:
            msg = f"Unexpected exception during processing: {e}"
            log.exception(msg)
            self.failed.emit(msg)
