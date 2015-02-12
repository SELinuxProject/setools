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
from . import qpol
from . import symbol
from . import objclass


def _is_mls(policy, symbol):
    # determine if this is a regular or MLS constraint/validatetrans.
    # this can only be determined by inspecting the expression.
    for expr_node in symbol.expr_iter(policy):
        sym_type = expr_node.sym_type(policy)
        expr_type = expr_node.expr_type(policy)

        if expr_type == qpol.QPOL_CEXPR_TYPE_ATTR and \
                sym_type >= qpol.QPOL_CEXPR_SYM_L1L2:
            return True

    return False


def constraint_factory(policy, symbol):
    """Factory function for creating regular (non-MLS) constraint objects."""

    try:
        if _is_mls(policy, symbol):
            raise TypeError(
                "Constraint symbol is not a regular (non-MLS) constraint.")
    except AttributeError:
        raise TypeError("Constraints cannot be looked-up.")

    return Constraint(policy, symbol)


def mlsconstraint_factory(policy, symbol):
    """Factory function for creating MLS constraint objects."""

    try:
        if not _is_mls(policy, symbol):
            raise TypeError("Constraint symbol is not a MLS constraint.")
    except AttributeError:
        raise TypeError("MLS constraints cannot be looked-up.")

    return MLSConstraint(policy, symbol)


def validatetrans_factory(policy, symbol):
    """Factory function for creating regular (non-MLS) validatetrans objects."""

    try:
        if _is_mls(policy, symbol):
            raise TypeError(
                "Validatetrans symbol is not a regular (non-MLS) constraint.")
    except AttributeError:
        raise TypeError("Validatetrans cannot be looked-up.")

    return ValidateTrans(policy, symbol)


def mlsvalidatetrans_factory(policy, symbol):
    """Factory function for creating MLS validatetrans objects."""

    try:
        if not _is_mls(policy, symbol):
            raise TypeError("Validatetrans symbol is not a MLS validatetrans.")
    except AttributeError:
        raise TypeError("MLS validatetrans cannot be looked-up.")

    return MLSValidateTrans(policy, symbol)


class Constraint(symbol.PolicySymbol):

    """A regular (non-MLS) constraint rule."""

    _expr_type_to_text = {
        qpol.QPOL_CEXPR_TYPE_NOT: "not",
        qpol.QPOL_CEXPR_TYPE_AND: "and",
        qpol.QPOL_CEXPR_TYPE_OR: "\n\tor"}

    _expr_op_to_text = {
        qpol.QPOL_CEXPR_OP_EQ: "==",
        qpol.QPOL_CEXPR_OP_NEQ: "!=",
        qpol.QPOL_CEXPR_OP_DOM: "dom",
        qpol.QPOL_CEXPR_OP_DOMBY: "domby",
        qpol.QPOL_CEXPR_OP_INCOMP: "incomp"}

    _sym_to_text = {
        qpol.QPOL_CEXPR_SYM_USER: "u1",
        qpol.QPOL_CEXPR_SYM_ROLE: "r1",
        qpol.QPOL_CEXPR_SYM_TYPE: "t1",
        qpol.QPOL_CEXPR_SYM_USER + qpol.QPOL_CEXPR_SYM_TARGET: "u2",
        qpol.QPOL_CEXPR_SYM_ROLE + qpol.QPOL_CEXPR_SYM_TARGET: "r2",
        qpol.QPOL_CEXPR_SYM_TYPE + qpol.QPOL_CEXPR_SYM_TARGET: "t2",
        qpol.QPOL_CEXPR_SYM_L1L2: "l1",
        qpol.QPOL_CEXPR_SYM_L1H2: "l1",
        qpol.QPOL_CEXPR_SYM_H1L2: "h1",
        qpol.QPOL_CEXPR_SYM_H1H2: "h1",
        qpol.QPOL_CEXPR_SYM_L1H1: "l1",
        qpol.QPOL_CEXPR_SYM_L2H2: "l2",
        qpol.QPOL_CEXPR_SYM_L1L2 + qpol.QPOL_CEXPR_SYM_TARGET: "l2",
        qpol.QPOL_CEXPR_SYM_L1H2 + qpol.QPOL_CEXPR_SYM_TARGET: "h2",
        qpol.QPOL_CEXPR_SYM_H1L2 + qpol.QPOL_CEXPR_SYM_TARGET: "l2",
        qpol.QPOL_CEXPR_SYM_H1H2 + qpol.QPOL_CEXPR_SYM_TARGET: "h2",
        qpol.QPOL_CEXPR_SYM_L1H1 + qpol.QPOL_CEXPR_SYM_TARGET: "h1",
        qpol.QPOL_CEXPR_SYM_L2H2 + qpol.QPOL_CEXPR_SYM_TARGET: "h2"}

    _expr_type_to_precedence = {
        qpol.QPOL_CEXPR_TYPE_NOT: 3,
        qpol.QPOL_CEXPR_TYPE_AND: 2,
        qpol.QPOL_CEXPR_TYPE_OR: 1}

    # all operators have the same precedence
    _expr_op_precedence = 4

    def __str__(self):
        rule_string = "constrain {0.tclass} ".format(self)

        perms = self.perms
        if len(perms) > 1:
            rule_string += "{{ {0} }} (\n".format(' '.join(perms))
        else:
            # convert to list since sets cannot be indexed
            rule_string += "{0} (\n".format(list(perms)[0])

        rule_string += "\t{0}\n);".format(self.__build_expression())

        return rule_string

    def __build_expression(self):
        # qpol representation is in postfix notation.  This code
        # converts it to infix notation.  Parentheses are added
        # to ensure correct expressions, though they may end up
        # being overused.  Set previous operator at start to the
        # highest precedence (op) so if there is a single binary
        # operator, no parentheses are output

        expr_string = ""
        stack = []
        prev_oper = self._expr_op_precedence
        for expr_node in self.qpol_symbol.expr_iter(self.policy):
            op = expr_node.op(self.policy)
            sym_type = expr_node.sym_type(self.policy)
            expr_type = expr_node.expr_type(self.policy)

            if expr_type == qpol.QPOL_CEXPR_TYPE_ATTR:
                stack.append([self._sym_to_text[sym_type],
                              self._expr_op_to_text[op],
                              self._sym_to_text[sym_type + qpol.QPOL_CEXPR_SYM_TARGET]])
                prev_oper = self._expr_op_precedence
            elif expr_type == qpol.QPOL_CEXPR_TYPE_NAMES:
                names = list(expr_node.names_iter(self.policy))

                if not names:
                    names_str = "<empty set>"
                elif len(names) == 1:
                    names_str = names[0]
                else:
                    names_str = "{{ {0} }}".format(' '.join(names))

                stack.append([self._sym_to_text[sym_type],
                              self._expr_op_to_text[op],
                              names_str])
                prev_oper = self._expr_op_precedence
            elif expr_type == qpol.QPOL_CEXPR_TYPE_NOT:
                # unary operator
                operand = stack.pop()
                stack.append([self._expr_type_to_text[expr_type],
                              "(",
                              operand,
                              ")"])
                prev_oper = self._expr_type_to_precedence[expr_type]
            else:
                operand1 = stack.pop()
                operand2 = stack.pop()

                # if previous operator is of higher precedence
                # no parentheses are needed.
                if self._expr_type_to_precedence[expr_type] < prev_oper:
                    stack.append([operand1,
                                  self._expr_type_to_text[expr_type],
                                  operand2])
                else:
                    stack.append(["(",
                                  operand1,
                                  self._expr_type_to_text[expr_type],
                                  operand2,
                                  ")"])

                prev_oper = self._expr_type_to_precedence[expr_type]

        return self.__unwind_subexpression(stack)

    def __unwind_subexpression(self, expr):
        ret = []

        # do a string.join on sublists (subexpressions)
        for i in expr:
            if isinstance(i, list):
                ret.append(self.__unwind_subexpression(i))
            else:
                ret.append(i)

        return ' '.join(ret)

    @property
    def perms(self):
        """The constraint's permission set."""

        return set(self.qpol_symbol.perm_iter(self.policy))

    def statement(self):
        return str(self)

    @property
    def tclass(self):
        """Object class for this constraint."""
        return objclass.class_factory(self.policy, self.qpol_symbol.object_class(self.policy))


class MLSConstraint(Constraint):

    def __str__(self):
        rule_string = "mlsconstrain {0.tclass} ".format(self)

        perms = self.perms
        if len(perms) > 1:
            rule_string += "{{ {0} }} (\n".format(' '.join(perms))
        else:
            # convert to list since sets cannot be indexed
            rule_string += "{0} (\n".format(list(perms)[0])

        rule_string += "\t{0}\n);".format(self.__build_expression())

        return rule_string


class ValidateTrans(Constraint):

    """A regular validate transition rule."""

    def __str__(self):
        rule_string = "validatetrans {0.tclass} ".format(self)

        perms = self.perms
        if len(perms) > 1:
            rule_string += "{{ {0} }} (\n".format(' '.join(perms))
        else:
            # convert to list since sets cannot be indexed
            rule_string += "{0} (\n".format(list(perms)[0])

        rule_string += "\t{0}\n);".format(self.__build_expression())

        return rule_string


class MLSValidateTrans(Constraint):

    """A MLS validate transition rule."""

    def __str__(self):
        rule_string = "mlsvalidatetrans {0.tclass} ".format(self)

        perms = self.perms
        if len(perms) > 1:
            rule_string += "{{ {0} }} (\n".format(' '.join(perms))
        else:
            # convert to list since sets cannot be indexed
            rule_string += "{0} (\n".format(list(perms)[0])

        rule_string += "\t{0}\n);".format(self.__build_expression())

        return rule_string
