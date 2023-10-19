# SPDX-License-Identifier: LGPL-2.1-only

from collections import OrderedDict
from contextlib import suppress

from PyQt5 import QtWidgets
import setools

from .name import NameCriteriaWidget

__all__ = ("MLSLevelRangeWidget",)


class MLSLevelRangeWidget(NameCriteriaWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of MLS levels and ranges.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 required: bool = False,
                 enable_range_opts: bool = False,
                 parent: QtWidgets.QWidget | None = None):

        # Not much we can do here. Leave all validation to the query.
        super().__init__(title, query, attrname, [], "", enable_regex=False,
                         required=required, parent=parent)

        # the rstrip("_") below is to avoid names like "range__overlap"
        self.criteria_opts = OrderedDict[str, QtWidgets.QRadioButton]()
        if enable_range_opts:
            equ = QtWidgets.QRadioButton("Equal", parent=self)
            equ.setChecked(True)
            equ.toggled.connect(self._update_range_opts)
            self.top_layout.addWidget(equ, 1, 0, 1, 1)
            self.criteria_opts[""] = equ

            ovl = QtWidgets.QRadioButton("Overlap", parent=self)
            ovl.setChecked(False)
            ovl.toggled.connect(self._update_range_opts)
            self.top_layout.addWidget(ovl, 1, 1, 1, 1)
            self.criteria_opts[f"{attrname.rstrip('_')}_overlap"] = ovl

            sub = QtWidgets.QRadioButton("Subset", parent=self)
            sub.setChecked(False)
            sub.toggled.connect(self._update_range_opts)
            self.top_layout.addWidget(sub, 2, 0, 1, 1)
            self.criteria_opts[f"{attrname.rstrip('_')}_subset"] = sub

            sup = QtWidgets.QRadioButton("Superset", parent=self)
            sup.setChecked(False)
            sup.toggled.connect(self._update_range_opts)
            self.top_layout.addWidget(sup, 2, 1, 1, 1)
            self.criteria_opts[f"{attrname.rstrip('_')}_superset"] = sup

    def _update_range_opts(self, value: bool = True) -> None:
        """Update the query based on the range opts radio button state."""
        if not value:
            return  # only apply updates once per radio button switch

        for name, w in self.criteria_opts.items():
            if name:  # empty means equal, which is the default
                self.log.debug(f"Setting {name} to {w.isChecked()}")
                setattr(self.query, name, w.isChecked())

    def save(self, settings: dict) -> None:
        super().save(settings)
        for name, w in self.criteria_opts.items():
            if name:
                settings[name] = w.isChecked()

    def load(self, settings: dict) -> None:
        for name, w in self.criteria_opts.items():
            if name:
                with suppress(AttributeError, KeyError):
                    w.setChecked(settings[name])

        super().load(settings)


if __name__ == '__main__':
    import sys
    import logging
    import warnings

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.MLSRuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = MLSLevelRangeWidget("Test Range", q, "default", enable_range_opts=True, parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    sys.exit(app.exec_())
