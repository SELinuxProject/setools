# SPDX-License-Identifier: LGPL-2.1-only
#
from typing import DefaultDict, Dict, List, Optional, TypeVar

from ..policyrep import PolicyObject, SELinuxPolicy

from .difference import Wrapper, SymbolWrapper


T = TypeVar("T", bound=PolicyObject)
U = TypeVar("U", bound=Wrapper)
Cache = DefaultDict[SELinuxPolicy, Dict[T, U]]
SymbolCache = Cache[T, SymbolWrapper[T]]

RuleList = Optional[DefaultDict[T, List[U]]]
