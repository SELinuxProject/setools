# Copyright 2020, Microsoft Corporation
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

import os
import logging
import unittest


from setools.checker import util


class CheckerUtilTest(unittest.TestCase):

    def test_config_bool_value(self):
        """Test config_bool_value"""
        self.assertTrue(util.config_bool_value(" TrUe "))
        self.assertTrue((util.config_bool_value(" 1 ")))
        self.assertTrue((util.config_bool_value(" YeS ")))
        self.assertFalse((util.config_bool_value(" FalsE ")))
        self.assertFalse((util.config_bool_value(" 0 ")))
        self.assertFalse((util.config_bool_value(" No ")))

        self.assertTrue(util.config_bool_value(True))
        self.assertFalse((util.config_bool_value(None)))
        self.assertFalse((util.config_bool_value(False)))
