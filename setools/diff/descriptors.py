# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from typing import MutableMapping
from weakref import WeakKeyDictionary


class DiffResultDescriptor:

    """Descriptor for managing diff results."""

    # @properties could be used instead, but there are so
    # many result attributes, this will keep the code cleaner.

    def __init__(self, diff_function: str) -> None:
        self.diff_function = diff_function

        # use weak references so instances can be
        # garbage collected, rather than unnecessarily
        # kept around due to this descriptor.
        self.instances: MutableMapping = WeakKeyDictionary()

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self

        if self.instances.setdefault(obj, None) is None:
            diff = getattr(obj, self.diff_function)
            diff()

        return self.instances[obj]

    def __set__(self, obj, value):
        self.instances[obj] = value

    def __delete__(self, obj):
        self.instances[obj] = None
