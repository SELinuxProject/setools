# Copyright 2014-2016, Tresys Technology, LLC
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
import itertools

from . import exception
from . import qpol
from . import rule
from . import typeattr
from . import boolcond


def te_rule_factory(policy, symbol):
    """Factory function for creating TE rule objects."""

    if isinstance(symbol, qpol.qpol_avrule_t):
        if symbol.is_extended(policy):
            return AVRuleXperm(policy, symbol)
        else:
            return AVRule(policy, symbol)
    elif isinstance(symbol, (qpol.qpol_terule_t, qpol.qpol_filename_trans_t)):
        return TERule(policy, symbol)
    else:
        raise TypeError("TE rules cannot be looked-up.")


def expanded_te_rule_factory(original, source, target):
    """
    Factory function for creating expanded TE rules.

    original    The TE rule the expanded rule originates from.
    source      The source type of the expanded rule.
    target      The target type of the expanded rule.
    """

    if isinstance(original, (ExpandedAVRule, ExpandedAVRuleXperm, ExpandedTERule)):
        return original
    elif isinstance(original, AVRuleXperm):
        rule = ExpandedAVRuleXperm(original.policy, original.qpol_symbol)
    elif isinstance(original, AVRule):
        rule = ExpandedAVRule(original.policy, original.qpol_symbol)
    elif isinstance(original, TERule):
        rule = ExpandedTERule(original.policy, original.qpol_symbol)
    else:
        raise TypeError("The original rule must be a TE rule class.")

    rule.source = source
    rule.target = target
    rule.origin = original
    return rule


def validate_ruletype(t):
    """Validate TE Rule types."""
    if t not in ["allow", "auditallow", "dontaudit", "neverallow",
                 "type_transition", "type_member", "type_change",
                 "allowxperm", "auditallowxperm", "dontauditxperm", "neverallowxperm"]:
        raise exception.InvalidTERuleType("{0} is not a valid TE rule type.".format(t))

    return t


class BaseTERule(rule.PolicyRule):

    """A type enforcement rule."""

    @property
    def source(self):
        """The rule's source type/attribute."""
        return typeattr.type_or_attr_factory(self.policy, self.qpol_symbol.source_type(self.policy))

    @property
    def target(self):
        """The rule's target type/attribute."""
        return typeattr.type_or_attr_factory(self.policy, self.qpol_symbol.target_type(self.policy))

    @property
    def filename(self):
        raise NotImplementedError

    @property
    def conditional(self):
        """The rule's conditional expression."""
        try:
            return boolcond.condexpr_factory(self.policy, self.qpol_symbol.cond(self.policy))
        except AttributeError:
            raise exception.RuleNotConditional

    @property
    def conditional_block(self):
        """The conditional block of the rule (T/F)"""
        try:
            return bool(self.qpol_symbol.which_list(self.policy))
        except AttributeError:
            raise exception.RuleNotConditional

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        for s, t in itertools.product(self.source.expand(), self.target.expand()):
            yield expanded_te_rule_factory(self, s, t)


class AVRule(BaseTERule):

    """An access vector type enforcement rule."""

    def __str__(self):
        try:
            return self._rule_string
        except AttributeError:
            self._rule_string = "{0.ruletype} {0.source} {0.target}:{0.tclass} ".format(self)

            # allow/dontaudit/auditallow/neverallow rules
            perms = self.perms
            if len(perms) > 1:
                self._rule_string += "{{ {0} }};".format(' '.join(perms))
            else:
                # convert to list since sets cannot be indexed
                self._rule_string += "{0};".format(list(perms)[0])

            try:
                self._rule_string += " [ {0.conditional} ]:{0.conditional_block}".format(self)
            except exception.RuleNotConditional:
                pass

        return self._rule_string

    @property
    def perms(self):
        """The rule's permission set."""
        return set(self.qpol_symbol.perm_iter(self.policy))

    @property
    def default(self):
        """The rule's default type."""
        raise exception.RuleUseError("{0} rules do not have a default type.".format(self.ruletype))

    @property
    def filename(self):
        raise exception.RuleUseError("{0} rules do not have file names".format(self.ruletype))


class ioctlSet(set):

    """
    A set with overridden string functions which compresses
    the output into ioctl ranges instead of individual elements.
    """

    def __format__(self, spec):
        """
        String formating.

        The standard formatting (no specification) will render the
        ranges of ioctls, space separated.

        The , option by itself will render the ranges of ioctls,
        comma separated

        Any other combination of formatting options will fall back
        to set's formatting behavior.
        """

        # generate short permission notation
        perms = sorted(self)
        shortlist = []
        for _, i in itertools.groupby(perms, key=lambda k, c=itertools.count(): k - next(c)):
            group = list(i)
            if len(group) > 1:
                shortlist.append("{0:#06x}-{1:#06x}".format(group[0], group[-1]))
            else:
                shortlist.append("{0:#06x}".format(group[0]))

        if not spec:
            return " ".join(shortlist)
        elif spec == ",":
            return ", ".join(shortlist)
        else:
            return super(ioctlSet, self).__format__(spec)

    def __str__(self):
        return "{0}".format(self)

    def __repr__(self):
        return "{{ {0:,} }}".format(self)

    def ranges(self):
        """
        Return the number of ranges in the set.  Main use
        is to determine if brackets need to be used in
        string output.
        """
        return sum(1 for (_a, _b) in itertools.groupby(
            sorted(self), key=lambda k, c=itertools.count(): k - next(c)))


class AVRuleXperm(AVRule):

    """An extended permission access vector type enforcement rule."""

    extended = True

    def __hash__(self):
        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{0.xperm_type}".format(self))

    def __str__(self):
        try:
            return self._rule_string
        except AttributeError:
            self._rule_string = "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.xperm_type} ". \
                                format(self)

            # generate short permission notation
            perms = self.perms
            if perms.ranges() > 1:
                self._rule_string += "{{ {0} }};".format(perms)
            else:
                self._rule_string += "{0};".format(perms)

        return self._rule_string

    @property
    def perms(self):
        """The rule's extended permission set."""
        return ioctlSet(self.qpol_symbol.xperm_iter(self.policy))

    @property
    def xperm_type(self):
        """The standard permission extended by these permissions (e.g. ioctl)."""
        return self.qpol_symbol.xperm_type(self.policy)


class TERule(BaseTERule):

    """A type_* type enforcement rule."""

    def __str__(self):
        try:
            return self._rule_string
        except AttributeError:
            self._rule_string = "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default}".format(
                self)

            try:
                self._rule_string += " \"{0}\";".format(self.filename)
            except (exception.TERuleNoFilename, exception.RuleUseError):
                # invalid use for type_change/member
                self._rule_string += ";"

            try:
                self._rule_string += " [ {0.conditional} ]:{0.conditional_block}".format(self)
            except exception.RuleNotConditional:
                pass

            return self._rule_string

    def __hash__(self):
        try:
            cond = self.conditional
            cond_block = self.conditional_block
        except exception.RuleNotConditional:
            cond = None
            cond_block = None

        try:
            filename = self.filename
        except (exception.TERuleNoFilename, exception.RuleUseError):
            filename = None

        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{1}|{2}|{3}".format(
            self, filename, cond, cond_block))

    @property
    def perms(self):
        """The rule's permission set."""
        raise exception.RuleUseError(
            "{0} rules do not have a permission set.".format(self.ruletype))

    @property
    def default(self):
        """The rule's default type."""
        return typeattr.type_factory(self.policy, self.qpol_symbol.default_type(self.policy))

    @property
    def filename(self):
        """The type_transition rule's file name."""
        try:
            return self.qpol_symbol.filename(self.policy)
        except AttributeError:
            if self.ruletype == "type_transition":
                raise exception.TERuleNoFilename
            else:
                raise exception.RuleUseError("{0} rules do not have file names".
                                             format(self.ruletype))


class ExpandedAVRule(AVRule):

    """An expanded access vector type enforcement rule."""

    source = None
    target = None
    origin = None


class ExpandedAVRuleXperm(AVRuleXperm):

    """An expanded extended permission access vector type enforcement rule."""

    source = None
    target = None
    origin = None


class ExpandedTERule(TERule):

    """An expanded type_* type enforcement rule."""

    source = None
    target = None
    origin = None
