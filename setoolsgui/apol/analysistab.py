# Copyright 2016, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from typing import Dict, NamedTuple
from enum import Enum

import sip
from PyQt5.QtWidgets import QDialogButtonBox, QScrollArea

from ..widget import SEToolsWidget


class AnalysisSection(Enum):

    """Groupings of analysis tabs"""

    Analysis = 1
    Components = 2
    General = 3
    Labeling = 4
    Other = 5
    Rules = 6


TAB_REGISTRY: Dict[str, type] = {}


class TabRegistry(sip.wrappertype):

    """
    Analysis tab registry metaclass.  This registers tabs to be used both for
    populating the content of the "choose analysis" dialog and also for
    saving tab/workspace info.
    """

    def __new__(cls, *args, **kwargs):
        classdef = super().__new__(cls, *args, **kwargs)

        clsname = args[0]
        attributedict = args[2]
        if clsname != "AnalysisTab":
            assert "section" in attributedict, "Class {} is missing the section value, " \
                "this is an setools bug".format(clsname)

            assert "tab_title" in attributedict, "Class {} is missing the tab_title value, " \
                "this is an setools bug".format(clsname)

            assert "mlsonly" in attributedict, "Class {} is missing the mlsonly value, " \
                "this is an setools bug".format(clsname)

            # ensure there is no duplication of class name or title
            for existing_tabname, existing_class in TAB_REGISTRY.items():
                if existing_tabname == clsname:
                    raise TypeError("Analysis tab {} conflicts with registered tab {}, "
                                    "this is an setools bug".format(clsname, existing_tabname))

                if existing_class.tab_title == attributedict["tab_title"]:
                    raise TypeError("Analysis tab {}'s title \"{}\" conflicts with registered tab "
                                    "{}, this is an setools bug.".
                                    format(clsname, attributedict["tab_title"], existing_tabname))

            TAB_REGISTRY[clsname] = classdef

        return classdef


# pylint: disable=invalid-metaclass
class AnalysisTab(SEToolsWidget, QScrollArea, metaclass=TabRegistry):

    """Base class for Apol analysis tabs."""

    # A QButtonBox which has an Apply button
    # for running the analysis.
    buttonBox = None

    # The set of tab fields that are in error
    errors = None

    # Normal and error palettes to use
    orig_palette = None
    error_palette = None

    #
    # Tab error state
    #
    def set_criteria_error(self, field, error):
        """Set the specified widget to an error state."""
        field.setToolTip("Error: {0}".format(error))
        field.setPalette(self.error_palette)
        self.errors.add(field)
        self._check_query()

    def clear_criteria_error(self, field, tooltip):
        """Clear the specified widget's error state."""
        field.setToolTip(tooltip)
        field.setPalette(self.orig_palette)
        self.errors.discard(field)
        self._check_query()

    def _check_query(self):
        button = self.buttonBox.button(QDialogButtonBox.Apply)
        enabled = not self.errors
        button.setEnabled(enabled)
        button.setToolTip("Run the analysis." if enabled else "There are errors in the tab.")

    #
    # Save/Load tab
    #
    def save(self):
        raise NotImplementedError

    def load(self, settings):
        raise NotImplementedError

    #
    # Results runner
    #
    def run(self, button):
        raise NotImplementedError

    def update_complete(self, count):
        raise NotImplementedError
