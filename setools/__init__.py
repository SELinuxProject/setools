"""The SETools SELinux policy analysis library."""
# Copyright 2014-2015, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
try:
    import pkg_resources
    __version__ = pkg_resources.get_distribution("setools").version
except:  # pragma: no cover
    __version__ = "unknown"

# Python classes for policy representation
from . import policyrep
from .policyrep import SELinuxPolicy, InvalidPolicy

# Component Queries
from . import boolquery
from . import categoryquery
from . import commonquery
from . import objclassquery
from . import polcapquery
from . import rolequery
from . import sensitivityquery
from . import typequery
from . import userquery

# Rule Queries
from . import mlsrulequery
from . import rbacrulequery
from . import terulequery

# Constraint queries
from . import constraintquery
from . import validatetransquery

# In-policy Context Queries
from . import fsusequery
from . import genfsconquery
from . import initsidquery
from . import netifconquery
from . import nodeconquery
from . import portconquery

# Information Flow Analysis
from . import infoflow
from . import permmap

# Domain Transition Analysis
from . import dta
