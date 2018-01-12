# Copyright 2014-2015, Tresys Technology, LLC
# Copyright Chris PeBenito <pebenito@ieee.org>
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
from itertools import chain, product
from collections import namedtuple


truth_table_row = namedtuple("truth_table_row", ["values", "result"])


#
# Boolean factory functions
#
cdef inline Boolean boolean_factory_lookup(SELinuxPolicy policy, str name):
    """Factory function variant for constructing Boolean objects by name."""

    cdef qpol_bool_t *symbol;
    if qpol_policy_get_bool_by_name(policy.handle, name.encode(), &symbol):
        raise InvalidBoolean("{0} is not a valid Boolean".format(name))

    return boolean_factory(policy, symbol)


cdef inline Boolean boolean_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Boolean objects."""
    return boolean_factory(policy, <const qpol_bool_t *> symbol.obj)


cdef inline Boolean boolean_factory(SELinuxPolicy policy, const qpol_bool_t *symbol):
    """Factory function for creating Boolean objects."""
    r = Boolean()
    r.policy = policy
    r.handle = symbol
    return r

#
# Conditional expression factory functions
#
cdef inline Conditional conditional_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Conditional objects."""
    return conditional_factory(policy, <const qpol_cond_t *> symbol.obj)


cdef inline Conditional conditional_factory(SELinuxPolicy policy, const qpol_cond_t *symbol):
    """Factory function for creating Conditional objects."""
    r = Conditional()
    r.policy = policy
    r.handle = symbol
    return r

#
# Conditional node factory functions
#
cdef inline object conditional_node_factory_iter(SELinuxPolicy policy, QpolIteratorItem item):
    """Factory function variant for iterating over conditional node objects."""
    cdef const qpol_cond_expr_node_t *symbol = <const qpol_cond_expr_node_t *> item.obj
    cdef uint32_t et
    cdef qpol_bool_t *b

    # Determine if this node is a Boolean or an operator
    if qpol_cond_expr_node_get_expr_type(policy.handle, symbol, &et):
        ex = LowLevelPolicyError("Error reading conditional expression node type: {}".format(
                                 strerror(errno)))
        ex.errno = errno
        raise ex

    if (et == QPOL_COND_EXPR_BOOL):
        if qpol_cond_expr_node_get_bool(policy.handle, symbol, &b):
            ex =  LowLevelPolicyError("Error reading boolean from conditional expression node: {}".
                                      format(strerror(errno)))
            ex.errno = errno
            raise ex

        return boolean_factory(policy, b)

    else:
        return conditional_op_factory(policy, symbol)


cdef inline ConditionalOperator conditional_op_factory(SELinuxPolicy policy, const qpol_cond_expr_node_t *symbol):
    """Factory function for creating conditional node objects."""
    op = ConditionalOperator()
    op.policy = policy
    op.handle = symbol
    return op


#
# Classes
#
cdef class Boolean(PolicySymbol):

    """A Boolean."""

    cdef const qpol_bool_t *handle

    def __str__(self):
        cdef const char *name

        if qpol_bool_get_name(self.policy.handle, self.handle, &name):
            ex = LowLevelPolicyError("Error reading Boolean name: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return intern(name)

    def _eq(self, Boolean other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def state(self):
        """The default state of the Boolean."""
        cdef int s
        if qpol_bool_get_state(self.policy.handle, self.handle, &s):
            ex = LowLevelPolicyError("Error reading boolean state: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return bool(s)

    def statement(self):
        """The policy statement."""
        return "bool {0} {1};".format(self, str(self.state).lower())


cdef class Conditional(PolicySymbol):

    """A conditional policy block."""

    cdef const qpol_cond_t *handle

    def __contains__(self, other):
        for b in self.booleans:
            if b == other:
                return True

        return False

    def __str__(self):
        # qpol representation is in postfix notation.  This code
        # converts it to infix notation.  Parentheses are added
        # to ensure correct expressions, though they may end up
        # being overused.  Set previous operator at start to the
        # highest precedence (NOT) so if there is a single binary
        # operator, no parentheses are output
        stack = []
        prev_op_precedence = 5

        for expr_node in self.expression():
            if isinstance(expr_node, Boolean):
                # append the boolean name
                stack.append(str(expr_node))
            elif expr_node.unary:
                operand = stack.pop()
                operator = str(expr_node)
                op_precedence = expr_node.precedence

                # NOT is the highest precedence, so only need
                # parentheses if the operand is a subexpression
                if isinstance(operand, list):
                    subexpr = [operator, "(", operand, ")"]
                else:
                    subexpr = [operator, operand]

                stack.append(subexpr)
                prev_op_precedence = op_precedence
            else:
                operand1 = stack.pop()
                operand2 = stack.pop()
                operator = str(expr_node)
                op_precedence = expr_node.precedence

                if prev_op_precedence > op_precedence:
                    # if previous operator is of higher precedence
                    # no parentheses are needed.
                    subexpr = [operand1, operator, operand2]
                else:
                    subexpr = ["(", operand1, operator, operand2, ")"]

                stack.append(subexpr)
                prev_op_precedence = op_precedence

        return self._unwind_subexpression(stack)

    def __hash__(self):
        return hash(<uintptr_t>self.handle)

    def __eq__(self, other):
        try:
            return self._eq(other)
        except TypeError:
            return str(self) == str(other)

    def _eq(self, Conditional other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    def _unwind_subexpression(self, expr):
        ret = []

        # do a string.join on sublists (subexpressions)
        for i in expr:
            if isinstance(i, list):
                ret.append(self._unwind_subexpression(i))
            else:
                ret.append(i)

        return ' '.join(ret)

    @property
    def booleans(self):
        """The set of Booleans in the expression."""
        return set(i for i in self.expression() if isinstance(i, Boolean))

    def evaluate(self, **kwargs):
        """
        Evaluate the expression with the stated boolean values.

        Keyword Parameters:
        Each keyword parameter name corresponds to a boolean name
        in the expression

        Return:     bool
        """
        bools = sorted(self.booleans)

        if sorted(kwargs.keys()) != bools:
            raise ValueError("All Booleans must have a specified value.")

        stack = []
        for expr_node in self.expression():
            if isinstance(expr_node, Boolean):
                stack.append(kwargs[expr_node])
            elif expr_node.unary:
                operand = stack.pop()
                operator = str(expr_node)
                stack.append(not operand)
            else:
                operand1 = stack.pop()
                operand2 = stack.pop()
                operator = str(expr_node)
                if operator == "||":
                    stack.append(operand1 or operand2)
                elif operator == "&&":
                    stack.append(operand1 and operand2)
                elif operator == "^":
                    stack.append(operand1 ^ operand2)
                elif operator == "==":
                    stack.append(operand1 == operand2)
                else:  # not equal
                    stack.append(operand1 != operand2)

        return stack[0]

    def expression(self):
        """Iterator over The conditional expression."""
        cdef qpol_iterator_t *iter;
        if qpol_cond_get_expr_node_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self.policy, iter, conditional_node_factory_iter)

    def false_rules(self):
        """An iterator over the rules in the false (else) block of the conditional."""
        cdef qpol_iterator_t *av_iter
        cdef qpol_iterator_t *te_iter

        cdef uint32_t av_rule_types = QPOL_RULE_ALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT \
            | QPOL_RULE_XPERMS_ALLOW | QPOL_RULE_XPERMS_AUDITALLOW | QPOL_RULE_XPERMS_DONTAUDIT

        cdef uint32_t te_rule_types = QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER

        if qpol_cond_get_av_false_iter(self.policy.handle, self.handle, av_rule_types, &av_iter):
            raise MemoryError

        if qpol_cond_get_te_false_iter(self.policy.handle, self.handle, te_rule_types, &te_iter):
            raise MemoryError

        return chain(qpol_iterator_factory(self.policy, av_iter, avrule_factory_iter),
                     qpol_iterator_factory(self.policy, te_iter, terule_factory_iter))

    def statement(self):
        raise NoStatement

    def true_rules(self):
        """An iterator over the rules in the true block of the conditional."""
        cdef qpol_iterator_t *av_iter
        cdef qpol_iterator_t *te_iter

        cdef uint32_t av_rule_types = QPOL_RULE_ALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT \
            | QPOL_RULE_XPERMS_ALLOW | QPOL_RULE_XPERMS_AUDITALLOW | QPOL_RULE_XPERMS_DONTAUDIT

        cdef uint32_t te_rule_types = QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER

        if qpol_cond_get_av_true_iter(self.policy.handle, self.handle, av_rule_types, &av_iter):
            raise MemoryError

        if qpol_cond_get_te_true_iter(self.policy.handle, self.handle, te_rule_types, &te_iter):
            raise MemoryError

        return chain(qpol_iterator_factory(self.policy, av_iter, avrule_factory_iter),
                     qpol_iterator_factory(self.policy, te_iter, terule_factory_iter))

    def truth_table(self):
        """
        Generate a truth table for this expression.

        Return:     list

        List item:
        tuple:      values, result

        Tuple item:
        values:     Dictionary keyed on Boolean names
                    with each value being T/F.
        result:     Evaluation result for the expression
                    given the values.
        """
        bools = sorted(str(b) for b in self.booleans)

        truth_table = []

        # create a list of all combinations of T/F for each Boolean
        truth_list = list(product([True, False], repeat=len(bools)))

        for row in truth_list:
            values = {bools[i]: row[i] for i in range(len(bools))}
            truth_table.append(truth_table_row(values, self.evaluate(**values)))

        return truth_table


cdef class ConditionalOperator(PolicySymbol):

    """A conditional expression operator"""

    cdef const qpol_cond_expr_node_t *handle

    _cond_expr_val_to_text = {
        QPOL_COND_EXPR_NOT: "!",
        QPOL_COND_EXPR_OR: "||",
        QPOL_COND_EXPR_AND: "&&",
        QPOL_COND_EXPR_XOR: "^",
        QPOL_COND_EXPR_EQ: "==",
        QPOL_COND_EXPR_NEQ: "!="}

    _cond_expr_val_to_precedence = {
        QPOL_COND_EXPR_NOT: 5,
        QPOL_COND_EXPR_OR: 1,
        QPOL_COND_EXPR_AND: 3,
        QPOL_COND_EXPR_XOR: 2,
        QPOL_COND_EXPR_EQ: 4,
        QPOL_COND_EXPR_NEQ: 4}

    def __str__(self):
        return self._cond_expr_val_to_text[self._type]

    def _eq(self, ConditionalOperator other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def _type(self):
        """The type of operator."""
        cdef uint32_t et
        if qpol_cond_expr_node_get_expr_type(self.policy.handle, self.handle, &et):
            ex = LowLevelPolicyError("Error reading conditional expression node type: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return et

    @property
    def precedence(self):
        """The precedence of this operator."""
        return self._cond_expr_val_to_precedence[self._type]

    @property
    def unary(self):
        """T/F the operator is unary"""
        return self._type == QPOL_COND_EXPR_NOT
