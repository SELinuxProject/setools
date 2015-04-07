# Copyright 2015, Tresys Technology, LLC
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

#
# Base class for exceptions
#


class SEToolsException(Exception):

    """Base class for all SETools exceptions."""
    pass

#
# Permission map exceptions
#


class PermissionMapException(SEToolsException):

    """Base class for all permission map exceptions."""
    pass


class PermissionMapParseError(PermissionMapException):

    """Exception for parse errors while reading permission map files."""
    pass


class RuleTypeError(PermissionMapException):

    """Exception for using rules with incorrect rule type."""
    pass


class UnmappedClass(PermissionMapException):

    """Exception for classes that are unmapped"""
    pass


class UnmappedPermission(PermissionMapException):

    """Exception for permissions that are unmapped"""
    pass
