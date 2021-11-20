# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#

from logging import Formatter, Handler, INFO
from PyQt5.QtCore import pyqtSignal, QObject


class LogHandlerToSignal(Handler, QObject):

    """
    A Python logging Handler that sends log messages over
    Qt signals.  By default the handler level is set to
    logging.INFO and only the message is signalled.

    Qt signals:
    message     (str) A message from the Python logging system.
    """

    message = pyqtSignal(str)

    def __init__(self):
        Handler.__init__(self)
        QObject.__init__(self)
        self.setLevel(INFO)
        self.setFormatter(Formatter('%(message)s'))

    def emit(self, record):
        msg = self.format(record)

        if msg:
            self.message.emit(msg)
