# SPDX-License-Identifier: LGPL-2.1-only
# Copyright 2016, Tresys Technology, LLC

import copy
import logging

from PyQt6 import QtCore, QtGui, QtWidgets
from setools import PermissionMap

from . import models, views


class PermissionMapEditor(QtWidgets.QDialog):

    """
    A permission map editor.  This dialog has two versions,
    one for editing the weight/direction and another for
    including or excluding permissions in an analysis.

    Parameters:
    parent      The parent Qt widget
    edit        (bool) If true, the dialog will take
                the editor behavior.  If False, the dialog
                will take the enable/disable permission
                behavior.
    """

    apply_permmap = QtCore.pyqtSignal(PermissionMap)
    class_toggle = QtCore.pyqtSignal(bool)

    def __init__(self, perm_map: PermissionMap, edit: bool = False,
                 parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.log = logging.getLogger(__name__)
        self.edit = edit

        # keep an internal copy because the map is mutable
        # and this dialog may be canceled after some edits.
        self.perm_map = copy.deepcopy(perm_map)

        if self.edit:
            self.setWindowTitle(f"{self.perm_map} - Permission Map Editor - apol")
        else:
            self.setWindowTitle(f"{self.perm_map} - Permission Map Viewer - apol")

        top_layout = QtWidgets.QVBoxLayout(self)

        #
        # Title
        #
        title = QtWidgets.QLabel(self)
        title.setObjectName("title")
        top_layout.addWidget(title)

        if self.edit:
            title.setText("Permission Map Editor")
        else:
            title.setText("Permission Map Viewer")

        frame = QtWidgets.QFrame(self)
        frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        frame_layout = QtWidgets.QGridLayout(frame)

        # set up class list
        self.classes = views.SEToolsListView(frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Maximum,
                                           QtWidgets.QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.classes.sizePolicy().hasHeightForWidth())
        self.classes.setSizePolicy(sizePolicy)
        self.classes.setModel(models.StringList(data=sorted(self.perm_map.classes()), parent=self))
        self.classes.selectionModel().selectionChanged.connect(self.class_selected)
        frame_layout.addWidget(self.classes, 0, 1, 1, 1)

        # Enable all button
        self.enable_all = QtWidgets.QPushButton(frame)
        self.enable_all.setText("Include All Permissions")
        frame_layout.addWidget(self.enable_all, 1, 2, 1, 1)

        # Disable all button
        self.disable_all = QtWidgets.QPushButton(frame)
        self.disable_all.setText("Exclude All Permissions")
        frame_layout.addWidget(self.disable_all, 1, 3, 1, 1)

        # permission widgets
        self.widgets = list[PermissionMapping | QtWidgets.QFrame]()
        scrollArea = QtWidgets.QScrollArea(frame)
        scrollArea.setWidgetResizable(True)
        scrollArea.setAlignment(
            QtCore.Qt.AlignmentFlag.AlignLeft |
            QtCore.Qt.AlignmentFlag.AlignTop)
        scrollAreaWidgetContents = QtWidgets.QWidget()
        scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 463, 331))
        self.perm_mappings = QtWidgets.QVBoxLayout(scrollAreaWidgetContents)
        scrollArea.setWidget(scrollAreaWidgetContents)
        frame_layout.addWidget(scrollArea, 0, 2, 1, 2)
        top_layout.addWidget(frame)

        self.buttonBox = QtWidgets.QDialogButtonBox(self)
        self.buttonBox.setOrientation(QtCore.Qt.Orientation.Horizontal)
        self.buttonBox.setStandardButtons(
            QtWidgets.QDialogButtonBox.StandardButton.Cancel |
            QtWidgets.QDialogButtonBox.StandardButton.Ok)
        top_layout.addWidget(self.buttonBox)

        # set up editor mode
        self.enable_all.setHidden(self.edit)
        self.disable_all.setHidden(self.edit)

        # connect signals
        self.enable_all.clicked.connect(self.enable_all_perms)
        self.disable_all.clicked.connect(self.disable_all_perms)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)
        QtCore.QMetaObject.connectSlotsByName(self)

    def accept(self) -> None:
        """Accept the dialog and emit the perm_map signal."""
        self.apply_permmap.emit(self.perm_map)
        super().accept()

    def class_selected(self) -> None:
        """Handle a class being selected."""
        # the widget is set to 1 selection
        selection_model = self.classes.selectionModel()
        assert selection_model, "No selection model set, this is an SETools bug."  # type narrowing
        data_model = self.classes.model()
        assert data_model, "No data model set, this is an SETools bug."  # type narrowing
        for index in selection_model.selectedIndexes():
            class_name = data_model.data(index, models.ModelRoles.DisplayRole)

        self.log.debug(f"Setting class to {class_name}")

        self.enable_all.setToolTip(f"Include all permissions in the {class_name} class.")
        self.disable_all.setToolTip(f"Exclude all permissions in the {class_name} class.")

        self._clear_mappings()

        # populate new mappings
        for perm in sorted(self.perm_map.perms(class_name)):
            # create permission mapping
            mapping = PermissionMapping(perm, self.edit, self)
            mapping.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)
            self.class_toggle.connect(mapping.enabled.setChecked)
            self.perm_mappings.addWidget(mapping)
            self.widgets.append(mapping)

            # add horizonal line
            line = QtWidgets.QFrame(self)
            line.setFrameShape(QtWidgets.QFrame.Shape.HLine)
            line.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
            self.perm_mappings.addWidget(line)
            self.widgets.append(line)

    def enable_all_perms(self) -> None:
        """Enable all permissions in the current class."""
        self.class_toggle.emit(True)

    def disable_all_perms(self) -> None:
        """Disable all permissions in the current class."""
        self.class_toggle.emit(False)

    #
    # Internal functions
    #
    def _clear_mappings(self):
        # delete current mappings
        for mapping in self.widgets:
            mapping.close()

        self.widgets.clear()


index_to_setting = ["r", "w", "b", "n"]
index_to_word = ["Read", "Write", "Both", "None"]
setting_to_index = {"r": 0, "w": 1, "b": 2, "n": 3}


class PermissionMapping(QtWidgets.QWidget):

    """
    A widget representing mapping for a particular permission.
    This dialog has two versions, one for editing the weight/direction
    and another for including or excluding permissions in an analysis.

    Parameters:
    parent      The parent Qt widget
    edit        (bool) If true, the widget will take
                the editor behavior.  If False, the dialog
                will take the enable/disable permission
                behavior.
    """

    def __init__(self, mapping, edit: bool = False, parent: PermissionMapEditor | None = None):
        super().__init__(parent)
        self.log = logging.getLogger(__name__)
        self.mapping = mapping
        self.edit = edit

        self.resize(457, 41)
        self.horizontalLayout = QtWidgets.QHBoxLayout(self)
        self.permission = QtWidgets.QLabel(self)
        self.permission.setText(str(self.mapping.perm))
        self.horizontalLayout.addWidget(self.permission)
        self.direction = QtWidgets.QComboBox(self)
        self.horizontalLayout.addWidget(self.direction)
        self.weight = QtWidgets.QSpinBox(self)
        self.weight.setMinimum(1)
        self.weight.setMaximum(10)
        self.weight.setSingleStep(1)
        self.weight.setValue(self.mapping.weight)
        self.horizontalLayout.addWidget(self.weight)
        self.enabled = QtWidgets.QCheckBox(self)
        self.enabled.setText("Include")
        self.enabled.setChecked(self.mapping.enabled)
        self.horizontalLayout.addWidget(self.enabled)

        if self.edit:
            self.weight.setToolTip(
                f"Set the information flow weight of \"{self.mapping.perm}\"")
            self.direction.setToolTip(
                f"Set the information flow direction of \"{self.mapping.perm}\"")
        else:
            self.enabled.setToolTip(
                f"Include or exclude \"{self.mapping.perm}\" from the analysis.")

        self.weight.setEnabled(self.edit)
        self.direction.setEnabled(self.edit)
        self.enabled.setHidden(self.edit)

        # setup color palettes for direction
        self.orig_palette = self.direction.palette()
        self.error_palette = self.direction.palette()
        self.error_palette.setColor(QtGui.QPalette.ColorRole.Button,
                                    QtCore.Qt.GlobalColor.red)
        self.error_palette.setColor(QtGui.QPalette.ColorRole.ButtonText,
                                    QtCore.Qt.GlobalColor.white)

        # setup direction
        self.direction.insertItems(0, index_to_word)
        if self.mapping.direction == 'u':
            # Temporarily add unmapped value to items
            self.direction.insertItem(len(index_to_word), "Unmapped")
            self.direction.setCurrentText("Unmapped")
            self.direction.setPalette(self.error_palette)
            self.unmapped = True
        else:
            self.direction.setCurrentIndex(setting_to_index[self.mapping.direction])
            self.unmapped = False

        # connect signals
        self.direction.currentIndexChanged.connect(self.set_direction)
        self.weight.valueChanged.connect(self.set_weight)
        self.enabled.toggled.connect(self.set_enabled)
        QtCore.QMetaObject.connectSlotsByName(self)

    def set_direction(self, value) -> None:
        """Set the direction for the mapping."""
        if self.unmapped:
            if value == "Unmapped":
                return

            # Remove unmapped item if setting the mapping.
            self.direction.removeItem(len(index_to_word))
            self.direction.setPalette(self.orig_palette)
            self.unmapped = False

        dir_ = index_to_setting[value]
        self.log.debug(f"Setting {self.mapping.class_}:{self.mapping.perm} direction to {dir_}")
        self.mapping.direction = dir_

    def set_weight(self, value: str | int) -> None:
        """Set the weight for the mapping."""
        self.log.debug(f"Setting {self.mapping.class_}:{self.mapping.perm} weight to {value}")
        self.mapping.weight = int(value)

    def set_enabled(self, value: bool) -> None:
        """Set the enabled value for the mapping."""
        self.log.debug(f"Setting {self.mapping.class_}:{self.mapping.perm} enabled to {value}")
        self.mapping.enabled = value


if __name__ == '__main__':
    import sys
    import warnings
    import setools

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    app = QtWidgets.QApplication(sys.argv)
    p = setools.SELinuxPolicy()
    m = setools.PermissionMap()
    m.map_policy(p)
    pview = PermissionMapEditor(m, edit=False)
    ped = PermissionMapEditor(m, edit=True)
    pview.show()
    ped.show()
    rc = app.exec()

    sys.exit(rc)
