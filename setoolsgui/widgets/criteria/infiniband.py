# SPDX-License-Identifier: LGPL-2.1-only

import typing

from PyQt6 import QtWidgets
import setools

from .criteria import OptionsPlacement
from .ipnetwork import IP_NetworkName
from .name import NameWidget
from .ranged import RangedWidget

ENDPORT_VALIDATION: typing.Final[str] = r"[0-9]+"
PKEY_NUM_VALIDATION: typing.Final[str] = r"[0-9]+(-[0-9]+)?"

__all__ = ("IB_EndPortName", "IB_PKeyName", "IB_PKeySubnetPrefixName")


class IB_EndPortName(NameWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of infiniband endports.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 required: bool = False,
                 parent: QtWidgets.QWidget | None = None):

        super().__init__(title, query, attrname, [], validation=ENDPORT_VALIDATION,
                         enable_regex=False, required=required, parent=parent)

        self.criteria.setPlaceholderText("e.g. 80")
        self.setToolTip("The endport of the infiniband port range.")


class IB_PKeyName(RangedWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of infinband partition key ranges.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 required: bool = False,
                 enable_range_opts: bool = False,
                 convert_range: bool = True,  # convert single port to a range, e.g. 80 -> 80-80
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 parent: QtWidgets.QWidget | None = None):

        super().__init__(title, query, attrname, validation=PKEY_NUM_VALIDATION,
                         enable_range_opts=enable_range_opts,
                         options_placement=options_placement,
                         required=required, parent=parent)

        self.convert_range = convert_range
        self.criteria.setPlaceholderText("e.g. 80 or 6000-61010")
        self.setToolTip("The partition key number or range.")

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


class IB_PKeySubnetPrefixName(IP_NetworkName):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of infiniband partition key
    subnet prefixes.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 required: bool = False,
                 enable_range_opts: bool = False,
                 parent: QtWidgets.QWidget | None = None):

        super().__init__(title, query, attrname, mode=IP_NetworkName.Mode.IPV6_ONLY,
                         required=required, enable_range_opts=enable_range_opts,
                         parent=parent)

        self.criteria.setPlaceholderText("e.g. ff00::")
        self.setToolTip("The subnet prefix of the infiniband partition key.")


if __name__ == '__main__':
    import sys
    import logging
    import warnings

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.IbendportconQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = IB_EndPortName("Test endport", q, "port", parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    sys.exit(app.exec())
