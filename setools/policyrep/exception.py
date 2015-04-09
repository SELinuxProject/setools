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
from ..exception import SEToolsException

#
# Policyrep base exception
#


class PolicyrepException(SEToolsException):

    """Base class for all policyrep exceptions."""
    pass


#
# General Policyrep exceptions
#


class InvalidPolicy(SyntaxError, PolicyrepException):

    """Exception for invalid policy."""
    pass


class MLSDisabled(PolicyrepException):

    """
    Exception when MLS is disabled.
    """
    pass


#
# Invalid component exceptions
#
class InvalidSymbol(ValueError, PolicyrepException):

    """
    Base class for invalid symbols.  Typically this is attempting to
    look up an object in the policy, but it does not exist.
    """
    pass


class InvalidBoolean(InvalidSymbol):

    """Exception for invalid Booleans."""
    pass


class InvalidCategory(InvalidSymbol):

    """Exception for invalid MLS categories."""
    pass


class InvalidClass(InvalidSymbol):

    """Exception for invalid object classes."""
    pass


class InvalidCommon(InvalidSymbol):

    """Exception for invalid common permission sets."""
    pass


class InvalidInitialSid(InvalidSymbol):

    """Exception for invalid initial sids."""
    pass


class InvalidLevel(InvalidSymbol):

    """
    Exception for an invalid level.
    """
    pass


class InvalidLevelDecl(InvalidSymbol):

    """
    Exception for an invalid level declaration.
    """
    pass


class InvalidRange(InvalidSymbol):

    """
    Exception for an invalid range.
    """
    pass


class InvalidRole(InvalidSymbol):

    """Exception for invalid roles."""
    pass


class InvalidSensitivity(InvalidSymbol):

    """
    Exception for an invalid sensitivity.
    """
    pass


class InvalidType(InvalidSymbol):

    """Exception for invalid types and attributes."""
    pass


class InvalidUser(InvalidSymbol):

    """Exception for invalid users."""
    pass

#
# Rule type exceptions
#


class InvalidRuleType(InvalidSymbol):

    """Exception for invalid rule types."""
    pass


class InvalidConstraintType(InvalidSymbol):

    """Exception for invalid constraint types."""
    # This is not a rule but is similar.
    pass


class InvalidMLSRuleType(InvalidRuleType):

    """Exception for invalid MLS rule types."""
    pass


class InvalidRBACRuleType(InvalidRuleType):

    """Exception for invalid RBAC rule types."""
    pass


class InvalidTERuleType(InvalidRuleType):

    """Exception for invalid TE rule types."""
    pass


#
# Object use errors
#
class SymbolUseError(PolicyrepException):

    """
    Base class for incorrectly using an object.  Typically this is
    for classes with strong similarities, but with slight variances in
    functionality, e.g. allow vs type_transition rules.
    """
    pass


class RuleUseError(SymbolUseError):

    """
    Base class for incorrect parameters for a rule.  For
    example, trying to get the permissions of a rule that has no
    permissions.
    """
    pass


class ConstraintUseError(SymbolUseError):

    """Exception when getting permissions from a validatetrans."""
    pass


class NoStatement(SymbolUseError):

    """
    Exception for objects that have no inherent statement, such
    as conditional expressions and MLS ranges.
    """
    pass


#
# Other exceptions
#
class NoCommon(PolicyrepException):

    """
    Exception when a class does not inherit a common permission set.
    """
    pass


class NoDefaults(InvalidSymbol):

    """Exception for classes that have no default_* statements."""
    pass


class RuleNotConditional(PolicyrepException):

    """
    Exception when getting the conditional expression for rules
    that are unconditional (not conditional).
    """
    pass


class TERuleNoFilename(PolicyrepException):

    """
    Exception when getting the file name of a
    type_transition rule that has no file name.
    """
    pass
