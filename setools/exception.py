# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#

#
# Base class for exceptions
#


class SEToolsException(Exception):

    """Base class for all SETools exceptions."""
    pass


#
# Policyrep base exception
#
class PolicyrepException(SEToolsException):

    """Base class for all policyrep exceptions."""
    pass


#
# General Policyrep exceptions
#
class LowLevelPolicyError(ValueError, PolicyrepException):

    """
    Exception for low-level policy errors.  This is typically due to
    errors accessing policy data structures.  The policy may be
    malformed or there may be an SETools bug."""
    pass


class InvalidPolicy(ValueError, PolicyrepException):

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


class InvalidPermission(InvalidSymbol):

    """
    Exception for an invalid permission.
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


class InvalidBoundsType(InvalidSymbol):

    """Exception for invalid *bounds rule types."""
    pass


class InvalidConstraintType(InvalidSymbol):

    """Exception for invalid constraint types."""
    pass


class InvalidDefaultType(InvalidRuleType):

    """Exception for invalid default_* types."""
    pass


class InvalidFSUseType(InvalidRuleType):

    """Exception for invalid fs_use_* types."""
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
class SymbolUseError(AttributeError, PolicyrepException):

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
# Default rule exceptions
#
class InvalidDefaultValue(InvalidSymbol):

    """Exception for invalid default (not source/target)"""
    pass


class InvalidDefaultRange(InvalidSymbol):

    """Exception for invalid default range"""
    pass


#
# Other exceptions
#
class NoCommon(AttributeError, PolicyrepException):

    """
    Exception when a class does not inherit a common permission set.
    """
    pass


class NoDefaults(InvalidSymbol):

    """Exception for classes that have no default_* statements."""
    pass


class RuleNotConditional(AttributeError, PolicyrepException):

    """
    Exception when getting the conditional expression for rules
    that are unconditional (not conditional).
    """
    pass


class TERuleNoFilename(AttributeError, PolicyrepException):

    """
    Exception when getting the file name of a
    type_transition rule that has no file name.
    """
    pass


#
# PolicyChecker exceptions
#
class InvalidCheckerConfig(SEToolsException):

    """Base class for invalid checker configurations."""
    pass


class InvalidCheckerModule(InvalidCheckerConfig):

    """Exception when an unknown checker module is requested."""
    pass


class InvalidCheckOption(InvalidCheckerConfig):

    """Exception for invalid options in a checker module."""
    pass


class InvalidCheckValue(InvalidCheckerConfig):

    """Exception for invalid values for a checker module's option."""
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
