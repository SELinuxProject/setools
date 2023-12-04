# SPDX-License-Identifier: LGPL-2.1-only

import typing

from PyQt6 import QtWidgets
import setools

from .criteria import OptionsPlacement
from .ranged import RangedWidget

VALIDATION = r"[0-9]+(-[0-9]+)?"

__all__ = ("IP_PortName",)


class IP_PortName(RangedWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of port ranges.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 required: bool = False,
                 enable_range_opts: bool = False,
                 convert_range: bool = True,  # convert single port to a range, e.g. 80 -> 80-80
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 parent: QtWidgets.QWidget | None = None):

        super().__init__(title, query, attrname, validation=VALIDATION,
                         enable_range_opts=enable_range_opts,
                         options_placement=options_placement,
                         required=required, parent=parent)

        self.convert_range = convert_range
        self.criteria.setPlaceholderText("e.g. 80 or 6000-61010")

    # @typing.override
    def set_criteria(self) -> None:
        """Set the criteria field in the query."""
        entered_value: typing.Final[str] = self.criteria.text()
        if not entered_value:  # handle empty string
            return

        if not self.convert_range:
            raise NotImplementedError

        try:
            name: str = self.criteria.objectName()
            final_value: tuple[int, int]

            entered_split = entered_value.split("-")

            match len(entered_split):
                case 2:
                    final_value = (int(entered_split[0]), int(entered_split[1]))
                case 1:
                    final_value = (int(entered_value), int(entered_value))
                case _:
                    # shouldn't be reachable due to the validation regex
                    raise ValueError(f"Invalid port range: \"{entered_value}\"")

            self.log.debug(f"Setting {name} {final_value!r}")
            setattr(self.query, name, final_value)
            self.editingFinished.emit(getattr(self.query, name))

        except Exception as e:
            self.set_criteria_error(str(e))
            self.log.debug(f"Error setting {name}: {e}", exc_info=True)


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
    widget = IP_PortName("Test Range", q, "default", enable_range_opts=True, parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    sys.exit(app.exec())
