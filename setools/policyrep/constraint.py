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
from . import qpol
from .exception import ConstraintUseError, InvalidConstraintType
from .role import role_factory
from .symbol import PolicySymbol
from .objclass import class_factory
from .typeattr import type_or_attr_factory
from .user import user_factory


def _is_mls(policy, sym):
    """Determine if this is a regular or MLS constraint/validatetrans."""
    # this can only be determined by inspecting the expression.
    for expr_node in sym.expr_iter(policy):
        sym_type = expr_node.sym_type(policy)
        expr_type = expr_node.expr_type(policy)

        if expr_type == qpol.QPOL_CEXPR_TYPE_ATTR and sym_type >= qpol.QPOL_CEXPR_SYM_L1L2:
            return True

    return False


def validate_ruletype(t):
    """Validate constraint rule types."""
    if t not in ["constrain", "mlsconstrain", "validatetrans", "mlsvalidatetrans"]:
        raise InvalidConstraintType("{0} is not a valid constraint type.".format(t))

    return t


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


class BaseConstraint(PolicySymbol):

    """Base class for constraint rules."""

    _role_syms = [qpol.QPOL_CEXPR_SYM_ROLE,
                  qpol.QPOL_CEXPR_SYM_ROLE + qpol.QPOL_CEXPR_SYM_TARGET,
                  qpol.QPOL_CEXPR_SYM_ROLE + qpol.QPOL_CEXPR_SYM_XTARGET]

    _type_syms = [qpol.QPOL_CEXPR_SYM_TYPE,
                  qpol.QPOL_CEXPR_SYM_TYPE + qpol.QPOL_CEXPR_SYM_TARGET,
                  qpol.QPOL_CEXPR_SYM_TYPE + qpol.QPOL_CEXPR_SYM_XTARGET]

    _user_syms = [qpol.QPOL_CEXPR_SYM_USER,
                  qpol.QPOL_CEXPR_SYM_USER + qpol.QPOL_CEXPR_SYM_TARGET,
                  qpol.QPOL_CEXPR_SYM_USER + qpol.QPOL_CEXPR_SYM_XTARGET]

    def __init__(self, policy, qpol_symbol, ruletype):
        PolicySymbol.__init__(self, policy, qpol_symbol)
        self.ruletype = ruletype

    def __str__(self):
        raise NotImplementedError

    # There is no levels function as specific
    # levels cannot be used in expressions, only
    # the l1, h1, etc. symbols

    @property
    def roles(self):
        """The roles used in the expression."""
        return set(self._get_symbols(self._role_syms, role_factory))

    @property
    def perms(self):
        raise NotImplementedError

    def statement(self):
        return str(self)

    @property
    def tclass(self):
        """Object class for this constraint."""
        return class_factory(self.policy, self.qpol_symbol.object_class(self.policy))

    @property
    def types(self):
        """The types and type attributes used in the expression."""

        return set(self._get_symbols(self._type_syms, type_or_attr_factory))

    @property
    def users(self):
        """The users used in the expression."""
        return set(self._get_symbols(self._user_syms, user_factory))

    def expression(self):
        """
        The constraint's expression in infix notation.

        Return: list
        """

        _precedence = {
            "not": 4,
            "and": 2,
            "or": 1,
            "==": 3,
            "!=": 3,
            "dom": 3,
            "domby": 3,
            "incomp": 3}

        _max_precedence = 4

        _operands = ["u1", "u2", "u3",
                     "r1", "r2", "r3",
                     "t1", "t2", "t3",
                     "l1", "l2",
                     "h1", "h2"]

        # qpol representation is in postfix notation.  This code
        # converts it to infix notation.  Parentheses are added
        # to ensure correct expressions, though they may end up
        # being overused.  Set previous operator at start to the
        # highest precedence (op) so if there is a single binary
        # operator, no parentheses are output
        stack = []
        prev_op_precedence = _max_precedence
        for op in self.postfix_expression():
            if isinstance(op, frozenset) or op in _operands:
                # operands
                stack.append(op)
            else:
                # operators
                if op == "not":
                    # unary operator
                    operator = op
                    operand = stack.pop()
                    op_precedence = _precedence[op]
                    stack.append([operator, "(", operand, ")"])
                else:
                    # binary operators
                    operand2 = stack.pop()
                    operand1 = stack.pop()
                    operator = op

                    # if previous operator is of higher precedence
                    # no parentheses are needed.
                    if _precedence[op] < prev_op_precedence:
                        stack.append([operand1, operator, operand2])
                    else:
                        stack.append(["(", operand1, operator, operand2, ")"])

                prev_op_precedence = _precedence[op]

        return self._flatten_expression(stack)

    def postfix_expression(self):
        """
        The constraint's expression in postfix notation.

        Return: list
        """

        _expr_type_to_text = {
            qpol.QPOL_CEXPR_TYPE_NOT: "not",
            qpol.QPOL_CEXPR_TYPE_AND: "and",
            qpol.QPOL_CEXPR_TYPE_OR: "or"}

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

        expression = []
        for expr_node in self.qpol_symbol.expr_iter(self.policy):
            op = expr_node.op(self.policy)
            sym_type = expr_node.sym_type(self.policy)
            expr_type = expr_node.expr_type(self.policy)

            if expr_type == qpol.QPOL_CEXPR_TYPE_ATTR:
                # logical operator with symbols (e.g. u1 == u2)
                operand1 = _sym_to_text[sym_type]
                operand2 = _sym_to_text[sym_type + qpol.QPOL_CEXPR_SYM_TARGET]
                operator = _expr_op_to_text[op]

                expression.extend([operand1, operand2, operator])
            elif expr_type == qpol.QPOL_CEXPR_TYPE_NAMES:
                # logical operator with type or attribute list (e.g. t1 == { spam_t eggs_t })
                operand1 = _sym_to_text[sym_type]
                operator = _expr_op_to_text[op]

                names = list(expr_node.names_iter(self.policy))

                if sym_type in self._role_syms:
                    operand2 = frozenset(role_factory(self.policy, n) for n in names)
                elif sym_type in self._type_syms:
                    operand2 = frozenset(type_or_attr_factory(self.policy, n) for n in names)
                else:
                    operand2 = frozenset(user_factory(self.policy, n) for n in names)

                expression.extend([operand1, operand2, operator])
            else:
                # individual operators (and/or/not)
                expression.append(_expr_type_to_text[expr_type])

        return expression

    #
    # Internal functions
    #
    def _flatten_expression(self, expr):
        """Flatten the expression into a flat list."""
        ret = []

        for i in expr:
            if isinstance(i, list):
                ret.extend(self._flatten_expression(i))
            else:
                ret.append(i)

        return ret

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

    @staticmethod
    def _expression_str(expr):
        """Generate the string representation of the expression."""
        ret = []

        for item in expr:
            if isinstance(item, frozenset):
                if len(item) > 1:
                    ret.append("{{ {0} }} ".format(" ".join(str(j) for j in item)))
                else:
                    ret.append("{0}".format(" ".join(str(j) for j in item)))
            else:
                ret.append(item)

        return " ".join(ret)


class Constraint(BaseConstraint):

    """A constraint rule (constrain/mlsconstrain)."""

    def __str__(self):
        rule_string = "{0.ruletype} {0.tclass} ".format(self)

        perms = self.perms
        if len(perms) > 1:
            rule_string += "{{ {0} }} (".format(' '.join(perms))
        else:
            # convert to list since sets cannot be indexed
            rule_string += "{0} (".format(list(perms)[0])

        rule_string += "{0});".format(self._expression_str(self.expression()))

        return rule_string

    @property
    def perms(self):
        """The constraint's permission set."""
        return set(self.qpol_symbol.perm_iter(self.policy))


class Validatetrans(BaseConstraint):

    """A validatetrans rule (validatetrans/mlsvalidatetrans)."""

    def __str__(self):
        return "{0.ruletype} {0.tclass} ({1});".format(self,
                                                       self._expression_str(self.expression()))

    @property
    def perms(self):
        raise ConstraintUseError("{0} rules do not have permissions.".format(self.ruletype))
