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
from . import exception
from . import qpol
from . import role
from . import symbol
from . import objclass
from . import typeattr
from . import user


def _is_mls(policy, sym):
    """Determine if this is a regular or MLS constraint/validatetrans."""
    # this can only be determined by inspecting the expression.
    for expr_node in sym.expr_iter(policy):
        sym_type = expr_node.sym_type(policy)
        expr_type = expr_node.expr_type(policy)

        if expr_type == qpol.QPOL_CEXPR_TYPE_ATTR and sym_type >= qpol.QPOL_CEXPR_SYM_L1L2:
            return True

    return False


def validate_ruletype(types):
    """Validate constraint rule types."""
    for t in types:
        if t not in ["constrain", "mlsconstrain", "validatetrans", "mlsvalidatetrans"]:
            raise exception.InvalidConstraintType("{0} is not a valid constraint type.".format(t))


def constraint_factory(policy, sym):
    """Factory function for creating constraint objects."""

    try:
        if _is_mls(policy, sym):
            if isinstance(sym, qpol.qpol_constraint_t):
                return Constraint(policy, sym, "mlsconstrain")
            else:
                return Validatetrans(policy, sym, "mlsvalidatetrans")
        else:
            if isinstance(sym, qpol.qpol_constraint_t):
                return Constraint(policy, sym, "constrain")
            else:
                return Validatetrans(policy, sym, "validatetrans")

    except AttributeError:
        raise TypeError("Constraints cannot be looked-up.")


class BaseConstraint(symbol.PolicySymbol):

    """Base class for constraint rules."""

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
        qpol.QPOL_CEXPR_SYM_USER + qpol.QPOL_CEXPR_SYM_XTARGET: "u3",
        qpol.QPOL_CEXPR_SYM_ROLE + qpol.QPOL_CEXPR_SYM_XTARGET: "r3",
        qpol.QPOL_CEXPR_SYM_TYPE + qpol.QPOL_CEXPR_SYM_XTARGET: "t3",
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

    # Boolean operators
    _expr_type_to_precedence = {
        qpol.QPOL_CEXPR_TYPE_NOT: 3,
        qpol.QPOL_CEXPR_TYPE_AND: 2,
        qpol.QPOL_CEXPR_TYPE_OR: 1}

    # Logical operators have the same precedence
    _logical_op_precedence = 4

    def __init__(self, policy, qpol_symbol, ruletype):
        symbol.PolicySymbol.__init__(self, policy, qpol_symbol)
        self.ruletype = ruletype

    def __str__(self):
        raise NotImplementedError

    def _build_expression(self):
        # qpol representation is in postfix notation.  This code
        # converts it to infix notation.  Parentheses are added
        # to ensure correct expressions, though they may end up
        # being overused.  Set previous operator at start to the
        # highest precedence (op) so if there is a single binary
        # operator, no parentheses are output

        stack = []
        prev_op_precedence = self._logical_op_precedence
        for expr_node in self.qpol_symbol.expr_iter(self.policy):
            op = expr_node.op(self.policy)
            sym_type = expr_node.sym_type(self.policy)
            expr_type = expr_node.expr_type(self.policy)

            if expr_type == qpol.QPOL_CEXPR_TYPE_ATTR:
                # logical operator with symbol (e.g. u1 == u2)
                operand1 = self._sym_to_text[sym_type]
                operand2 = self._sym_to_text[sym_type + qpol.QPOL_CEXPR_SYM_TARGET]
                operator = self._expr_op_to_text[op]

                stack.append([operand1, operator, operand2])

                prev_op_precedence = self._logical_op_precedence
            elif expr_type == qpol.QPOL_CEXPR_TYPE_NAMES:
                # logical operator with type or attribute list (e.g. t1 == { spam_t eggs_t })
                operand1 = self._sym_to_text[sym_type]
                operator = self._expr_op_to_text[op]

                names = list(expr_node.names_iter(self.policy))

                if not names:
                    operand2 = "<empty set>"
                elif len(names) == 1:
                    operand2 = names[0]
                else:
                    operand2 = "{{ {0} }}".format(' '.join(names))

                stack.append([operand1, operator, operand2])

                prev_op_precedence = self._logical_op_precedence
            elif expr_type == qpol.QPOL_CEXPR_TYPE_NOT:
                # unary operator (not)
                operand = stack.pop()
                operator = self._expr_type_to_text[expr_type]

                stack.append([operator, "(", operand, ")"])

                prev_op_precedence = self._expr_type_to_precedence[expr_type]
            else:
                # binary operator (and/or)
                operand1 = stack.pop()
                operand2 = stack.pop()
                operator = self._expr_type_to_text[expr_type]
                op_precedence = self._expr_type_to_precedence[expr_type]

                # if previous operator is of higher precedence
                # no parentheses are needed.
                if op_precedence < prev_op_precedence:
                    stack.append([operand1, operator, operand2])
                else:
                    stack.append(["(", operand1, operator, operand2, ")"])

                prev_op_precedence = op_precedence

        return self.__unwind_subexpression(stack)

    def _get_symbols(self, syms, factory):
        """
        Internal generator for getting users/roles/types in a constraint
        expression.  Symbols will be yielded multiple times if they appear
        in the expression multiple times.

        Parameters:
        syms        List of qpol symbol types.
        factory     The factory function related to these symbols.
        """
        for expr_node in self.qpol_symbol.expr_iter(self.policy):
            sym_type = expr_node.sym_type(self.policy)
            expr_type = expr_node.expr_type(self.policy)

            if expr_type == qpol.QPOL_CEXPR_TYPE_NAMES and sym_type in syms:
                for s in expr_node.names_iter(self.policy):
                    yield factory(self.policy, s)

    def __unwind_subexpression(self, expr):
        ret = []

        # do a string.join on sublists (subexpressions)
        for i in expr:
            if isinstance(i, list):
                ret.append(self.__unwind_subexpression(i))
            else:
                ret.append(i)

        return ' '.join(ret)

    # There is no levels function as specific
    # levels cannot be used in expressions, only
    # the l1, h1, etc. symbols

    @property
    def roles(self):
        """The roles used in the expression."""
        role_syms = [qpol.QPOL_CEXPR_SYM_ROLE,
                     qpol.QPOL_CEXPR_SYM_ROLE + qpol.QPOL_CEXPR_SYM_TARGET,
                     qpol.QPOL_CEXPR_SYM_ROLE + qpol.QPOL_CEXPR_SYM_XTARGET]

        return set(self._get_symbols(role_syms, role.role_factory))

    @property
    def perms(self):
        raise NotImplementedError

    def statement(self):
        return str(self)

    @property
    def tclass(self):
        """Object class for this constraint."""
        return objclass.class_factory(self.policy, self.qpol_symbol.object_class(self.policy))

    @property
    def types(self):
        """The types and type attributes used in the expression."""
        type_syms = [qpol.QPOL_CEXPR_SYM_TYPE,
                     qpol.QPOL_CEXPR_SYM_TYPE + qpol.QPOL_CEXPR_SYM_TARGET,
                     qpol.QPOL_CEXPR_SYM_TYPE + qpol.QPOL_CEXPR_SYM_XTARGET]

        return set(self._get_symbols(type_syms, typeattr.type_or_attr_factory))

    @property
    def users(self):
        """The users used in the expression."""
        user_syms = [qpol.QPOL_CEXPR_SYM_USER,
                     qpol.QPOL_CEXPR_SYM_USER + qpol.QPOL_CEXPR_SYM_TARGET,
                     qpol.QPOL_CEXPR_SYM_USER + qpol.QPOL_CEXPR_SYM_XTARGET]

        return set(self._get_symbols(user_syms, user.user_factory))


class Constraint(BaseConstraint):

    """A constraint rule (constrain/mlsconstrain)."""

    def __str__(self):
        rule_string = "{0.ruletype} {0.tclass} ".format(self)

        perms = self.perms
        if len(perms) > 1:
            rule_string += "{{ {0} }} (\n".format(' '.join(perms))
        else:
            # convert to list since sets cannot be indexed
            rule_string += "{0} (\n".format(list(perms)[0])

        rule_string += "\t{0}\n);".format(self._build_expression())

        return rule_string

    @property
    def perms(self):
        """The constraint's permission set."""
        return set(self.qpol_symbol.perm_iter(self.policy))


class Validatetrans(BaseConstraint):

    """A validatetrans rule (validatetrans/mlsvalidatetrans)."""

    def __str__(self):
        return "{0.ruletype} {0.tclass}\n\t{1}\n);".format(self, self._build_expression())

    @property
    def perms(self):
        raise exception.ConstraintUseError("{0} rules do not have permissions.".
                                           format(self.ruletype))
