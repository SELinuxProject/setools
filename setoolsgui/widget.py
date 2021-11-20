# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import sys
from errno import ENOENT

import pkg_resources
from PyQt5.uic import loadUi


# Stylesheet that adds a frame around QGroupBoxes
stylesheet = "\
QGroupBox {\
    border: 1px solid lightgrey;\
    margin-top: 0.5em;\
    }\
\
QGroupBox::title {\
    subcontrol-origin: margin;\
    left: 10px;\
    padding: 0 3px 0 3px;\
}\
"


class SEToolsWidget:
    def load_ui(self, filename):
        distro = pkg_resources.get_distribution("setools")
        path = "{0}/setoolsgui/{1}".format(distro.location, filename)
        loadUi(path, self)

        self.setStyleSheet(stylesheet)
