"""The SETools SELinux policy analysis library."""
# Copyright 2014, Tresys Technology, LLC
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
except:
    __version__ = "unknown"

# Python classes for policy representation
import policyrep
from policyrep import SELinuxPolicy

# Component Queries
import commonquery
import objclassquery
import typequery
import rolequery
import userquery
import boolquery
import polcapquery
import permissivequery

# Rule Queries
import terulequery
import rbacrulequery
import mlsrulequery

# In-policy Context Queries
import initsidquery

# Information Flow Analysis
import infoflow
import permmap

# Domain Transition Analysis
import dta
