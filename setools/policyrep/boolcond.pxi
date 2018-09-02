# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2017-2018 Chris PeBenito <pebenito@ieee.org>
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

truth_table_row = collections.namedtuple("truth_table_row", ["values", "result"])

cdef dict _cond_cache = {}

#
# Classes
#
cdef class Boolean(PolicySymbol):

    """A Boolean."""

    cdef:
        uintptr_t key
        readonly object state

    @staticmethod
    cdef inline Boolean factory(SELinuxPolicy policy, sepol.cond_bool_datum_t *symbol):
        """Factory function for creating Boolean objects."""
        cdef Boolean b = Boolean.__new__(Boolean)
        b.policy = policy
        b.key = <uintptr_t>symbol
        b.name = policy.boolean_value_to_name(symbol.s.value - 1)
        b.state = <bint>symbol.state
        return b

    def _eq(self, Boolean other):
        """Low-level equality check (C pointers)."""
        return self.key == other.key

    def statement(self):
        """The policy statement."""
        return "bool {0} {1};".format(self.name, str(self.state).lower())


cdef class Conditional(PolicyObject):

    """A conditional policy block."""

    cdef:
        sepol.cond_node_t *handle
        list _postfix_expression
        readonly frozenset booleans

    @staticmethod
    cdef inline Conditional factory(SELinuxPolicy policy, sepol.cond_node_t *symbol):
        """Factory function for creating Conditional objects."""
        cdef:
            Conditional c
            list booleans

        try:
            return _cond_cache[<uintptr_t>symbol]
        except KeyError:
            c = Conditional.__new__(Conditional)
            _cond_cache[<uintptr_t>symbol] = c
            c.policy = policy
            c.handle = symbol
            c._postfix_expression = []
            booleans = []

            # Build expression list and boolean attribute
            for n in ConditionalExprIterator.factory(policy, <sepol.cond_expr_t *>symbol.expr):
                c._postfix_expression.append(n)
                if isinstance(n, Boolean):
                    booleans.append(n)

            c.booleans = frozenset(booleans)
            return c

    def __contains__(self, other):
        return other in self.booleans

    def __str__(self):
        # sepol representation is in postfix notation.  This code
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
        return iter(self._postfix_expression)

    def false_rules(self):
        """An iterator over the rules in the false (else) block of the conditional."""
        return ConditionalTERuleIterator.factory(self.policy, self.handle.false_list, self, False)

    def statement(self):
        raise NoStatement

    def true_rules(self):
        """An iterator over the rules in the true block of the conditional."""
        return ConditionalTERuleIterator.factory(self.policy, self.handle.true_list, self, True)

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
        truth_list = list(itertools.product([True, False], repeat=len(bools)))

        for row in truth_list:
            values = {bools[i]: row[i] for i in range(len(bools))}
            truth_table.append(truth_table_row(values, self.evaluate(**values)))

        return truth_table


cdef class ConditionalOperator(PolicyObject):

    """A conditional expression operator"""

    cdef:
        str text
        readonly int precedence
        # T/F the operator is unary
        readonly bint unary

    _cond_expr_val_to_text = {
        sepol.COND_NOT: "!",
        sepol.COND_OR: "||",
        sepol.COND_AND: "&&",
        sepol.COND_XOR: "^",
        sepol.COND_EQ: "==",
        sepol.COND_NEQ: "!="}

    _cond_expr_val_to_precedence = {
        sepol.COND_NOT: 5,
        sepol.COND_OR: 1,
        sepol.COND_AND: 3,
        sepol.COND_XOR: 2,
        sepol.COND_EQ: 4,
        sepol.COND_NEQ: 4}

    @staticmethod
    cdef inline ConditionalOperator factory(SELinuxPolicy policy, sepol.cond_expr_t *symbol):
        """Factory function for conditional operators."""
        cdef ConditionalOperator op = ConditionalOperator.__new__(ConditionalOperator)
        op.policy = policy
        op.unary = symbol.expr_type == sepol.COND_NOT
        op.precedence = op._cond_expr_val_to_precedence[symbol.expr_type]
        op.text = op._cond_expr_val_to_text[symbol.expr_type]
        return op

    def __str__(self):
        return self.text


#
# Iterators
#
cdef class BooleanHashtabIterator(HashtabIterator):

    """Iterate over Booleans in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating Boolean iterators."""
        i = BooleanHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return Boolean.factory(self.policy, <sepol.cond_bool_datum_t *>self.curr.datum)


cdef class ConditionalIterator(PolicyIterator):

    """Conditionals iterator."""

    cdef:
        sepol.cond_node_t *head
        sepol.cond_node_t *curr

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.cond_node_t *head):
        """Constraint iterator factory."""
        c = ConditionalIterator()
        c.policy = policy
        c.head = head
        c.reset()
        return c

    def __next__(self):
        if self.curr == NULL:
            raise StopIteration

        item = Conditional.factory(self.policy, self.curr)
        self.curr = self.curr.next
        return item

    def __len__(self):
        cdef:
            sepol.cond_node_t *curr
            size_t count = 0

        curr = self.head
        while curr != NULL:
             count += 1
             curr = curr.next

        return count

    def reset(self):
        """Reset the iterator back to the start."""
        self.curr = self.head


cdef class ConditionalExprIterator(PolicyIterator):

    """Conditional expression iterator."""

    cdef:
        sepol.cond_expr_t *head
        sepol.cond_expr_t *curr

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.cond_expr_t *head):
        """Conditional expression iterator factory."""
        e = ConditionalExprIterator()
        e.policy = policy
        e.head = head
        e.reset()
        return e

    def __next__(self):
        if self.curr == NULL:
            raise StopIteration

        if self.curr.expr_type == sepol.COND_BOOL:
            item = Boolean.factory(self.policy,
                                   self.policy.boolean_value_to_datum(self.curr.bool - 1))
        else:
            item = ConditionalOperator.factory(self.policy, self.curr)

        self.curr = self.curr.next
        return item

    def __len__(self):
        cdef:
            sepol.cond_expr_t *curr
            size_t count = 0

        curr = self.head
        while curr != NULL:
             count += 1
             curr = curr.next

        return count

    def reset(self):
        """Reset the iterator back to the start."""
        self.curr = self.head
