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
import setools.qpol as qpol
import string
import symbol


class Boolean(symbol.PolicySymbol):

    """A Boolean."""

    def state(self):
        """The default state of the Boolean."""
        return bool(self.qpol_symbol.get_state(self.policy))

    def statement(self):
        """The policy statement."""
        return "bool {0} {1};".format(self, str(self.state()).lower())


class ConditionalExpr(symbol.PolicySymbol):

    """A conditional policy expression."""

    _cond_expr_val_to_text = {
        qpol.QPOL_COND_EXPR_NOT: "!",
        qpol.QPOL_COND_EXPR_OR: "||",
        qpol.QPOL_COND_EXPR_AND: "&&",
        qpol.QPOL_COND_EXPR_XOR: "^",
        qpol.QPOL_COND_EXPR_EQ: "==",
        qpol.QPOL_COND_EXPR_NEQ: "!="}

    _cond_expr_val_to_precedence = {
        qpol.QPOL_COND_EXPR_NOT: 5,
        qpol.QPOL_COND_EXPR_OR: 1,
        qpol.QPOL_COND_EXPR_AND: 3,
        qpol.QPOL_COND_EXPR_XOR: 2,
        qpol.QPOL_COND_EXPR_EQ: 4,
        qpol.QPOL_COND_EXPR_NEQ: 4}

    def __str__(self):
        qpol_iter = self.qpol_symbol.get_expr_node_iter(self.policy)

        # qpol representation is in postfix notation.  This code
        # converts it to infix notation.  Parentheses are added
        # to ensure correct expressions, though they may end up
        # being overused.  Set previous operator at start to the
        # highest precedence (NOT) so if there is a single binary
        # operator, no parentheses are output
        stack = []
        prev_oper = qpol.QPOL_COND_EXPR_NOT
        while not qpol_iter.end():
            expr_node = qpol.qpol_cond_expr_node_from_void(
                qpol_iter.get_item())
            expr_node_type = expr_node.get_expr_type(self.policy)

            if expr_node_type == qpol.QPOL_COND_EXPR_BOOL:
                # append the boolean name
                nodebool = Boolean(
                    self.policy, expr_node.get_bool(self.policy))
                stack.append(str(nodebool))
            elif expr_node_type == qpol.QPOL_COND_EXPR_NOT:  # unary operator
                operand = stack.pop()

                # NOT is the highest precedence, so only need
                # parentheses if the operand is a subexpression
                if isinstance(operand, list):
                    subexpr = [
                        self._cond_expr_val_to_text[expr_node_type], "(", operand, ")"]
                else:
                    subexpr = [
                        self._cond_expr_val_to_text[expr_node_type], operand]

                stack.append(subexpr)
                prev_oper = expr_node_type
            else:
                operand1 = stack.pop()
                operand2 = stack.pop()

                if self._cond_expr_val_to_precedence[prev_oper] > \
                        self._cond_expr_val_to_precedence[expr_node_type]:
                    # if previous operator is of higher precedence
                    # no parentheses are needed.
                    subexpr = [
                        operand1, self._cond_expr_val_to_text[expr_node_type], operand2]
                else:
                    subexpr = [
                        "(", operand1, self._cond_expr_val_to_text[expr_node_type], operand2, ")"]

                stack.append(subexpr)
                prev_oper = expr_node_type

            qpol_iter.next()

        return self.__unwind_subexpression(stack)

    def __unwind_subexpression(self, expr):
        ret = []

        # do a string.join on sublists (subexpressions)
        for i in expr:
            if isinstance(i, list):
                ret.append(self.__unwind_subexpression(i))
            else:
                ret.append(i)

        return string.join(ret)
