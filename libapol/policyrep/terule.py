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
import string

import setools.qpol as qpol

import symbol
import rule
import typeattr
import objclass
import boolcond


class TERuleNoFilename(Exception):

    """
    Exception when getting the file name of a
    type_transition rule that has no file name.
    """
    pass


class TERule(rule.PolicyRule):

    """A type enforcement rule."""

    # This class abstracts away the policydb implementation detail
    # that 'AV' rules and 'TE' rules are in separate tables

    _teruletype_val_to_text = {
        qpol.QPOL_RULE_ALLOW: 'allow',
        qpol.QPOL_RULE_NEVERALLOW: 'neverallow',
        qpol.QPOL_RULE_DONTAUDIT: 'dontaudit',
        qpol.QPOL_RULE_AUDITALLOW: 'auditallow',
        qpol.QPOL_RULE_TYPE_TRANS: 'type_transition',
        qpol.QPOL_RULE_TYPE_CHANGE: 'type_change',
        qpol.QPOL_RULE_TYPE_MEMBER: 'type_member'}

    def __str__(self):
        rule_string = "{0.ruletype} {0.source} {0.target}:{0.tclass} ".format(
            self)

        try:
            perms = self.perms
        except rule.InvalidRuleUse:
            # type_* rules
            rule_string += str(self.default)

            try:
                rule_string += " \"{0}\";".format(self.filename)
            except TERuleNoFilename:
                rule_string += ";"
        else:
            # allow/dontaudit/auditallow/neverallow rules
            if len(perms) > 1:
                rule_string += "{{ {0} }};".format(string.join(perms))
            else:
                # convert to list since sets cannot be indexed
                rule_string += "{0};".format(list(perms)[0])

        try:
            rule_string += " [ {0} ]".format(self.conditional)
        except rule.RuleNotConditional:
            pass

        return rule_string

    @property
    def ruletype(self):
        """The rule type."""
        try:
            return self._teruletype_val_to_text[self.qpol_symbol.get_rule_type(self.policy)]
        except AttributeError:
            # qpol does not have a rule type function for name filetrans rules
            return "type_transition"

    @property
    def source(self):
        """The rule's source type/attribute."""
        return typeattr.TypeAttr(self.policy, self.qpol_symbol.get_source_type(self.policy))

    @property
    def target(self):
        """The rule's target type/attribute."""
        return typeattr.TypeAttr(self.policy, self.qpol_symbol.get_target_type(self.policy))

    @property
    def tclass(self):
        """The rule's object class."""
        return objclass.ObjClass(self.policy, self.qpol_symbol.get_object_class(self.policy))

    @property
    def perms(self):
        """The rule's permission set."""
        try:
            # create permission list
            iter = self.qpol_symbol.get_perm_iter(self.policy)
        except AttributeError:
            raise rule.InvalidRuleUse(
                "{0} rules do not have a permission set.".format(self.ruletype))

        p = set()

        while not iter.end():
            p.add(qpol.to_str(iter.get_item()))
            iter.next()

        return p

    @property
    def default(self):
        """The rule's default type."""
        try:
            return typeattr.TypeAttr(self.policy, self.qpol_symbol.get_default_type(self.policy))
        except AttributeError:
            raise rule.InvalidRuleUse(
                "{0} rules do not have a default type.".format(self.ruletype))

    @property
    def filename(self):
        """The type_transition rule's file name."""
        try:
            return self.qpol_symbol.get_filename(self.policy)
        except AttributeError:
            if self.ruletype == "type_transition":
                raise TERuleNoFilename
            else:
                raise rule.InvalidRuleUse(
                    "{0} rules do not have file names".format(self.ruletype))

    @property
    def conditional(self):
        """The rule's conditional expression."""
        try:
            return boolcond.ConditionalExpr(self.policy, self.qpol_symbol.get_cond(self.policy))
        except (AttributeError, symbol.InvalidSymbol):
            # AttributeError: name filetrans rules cannot be conditional
            #                 so no member function
            # InvalidSymbol:  The rule does not have a conditional,
            #                 so qpol returns a bad symbol (a None)
            raise rule.RuleNotConditional
