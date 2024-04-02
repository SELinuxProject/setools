# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#

from collections.abc import Callable
import typing

T = typing.TypeVar("T")


class DiffResultDescriptor(typing.Generic[T]):

    """Descriptor for managing diff results."""

    # @properties could be used instead, but there are so
    # many result attributes, this will keep the code cleaner.

    def __init__(self, diff_function: Callable[[typing.Any], None]) -> None:
        self.diff_function = diff_function
        self.name: str

    def __set_name__(self, owner, name: str) -> None:
        self.name = f"_internal_{name}"

    def __get__(self, obj, objtype=None) -> list[T]:
        if obj is None:
            raise AttributeError

        if getattr(obj, self.name, None) is None:
            # must specify obj here since the function is not bound to a
            # a particular instance.  Otherwise you get:
            # TypeError: av_diff_template.<locals>.diff() missing 1 required
            # positional argument: 'self'
            self.diff_function(obj)

        return getattr(obj, self.name)

    def __set__(self, obj, value: list[T]) -> None:
        setattr(obj, self.name, value)

    def __delete__(self, obj) -> None:
        setattr(obj, self.name, None)
