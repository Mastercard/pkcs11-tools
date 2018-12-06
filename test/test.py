#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2018 Mastercard

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import unittest
from subprocess import PIPE, Popen

#
# trick from http://stackoverflow.com/questions/2798956/python-unittest-generate-multiple-tests-programmatically
#
def create_test_req(commandline):
    def do_test_req(self):
        p1 = Popen( commandline.split(), stdout=PIPE);
        p2 = Popen( "openssl req -verify -noout".split(), stdin=p1.stdout, stdout=PIPE);
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()
        self.assertTrue(p2.returncode==0)
    return do_test_req


class TestReq(unittest.TestCase):
    pass


if __name__ == '__main__':

    k=0
    with open('reqtestcases.txt') as testcases:
        for testcase  in testcases:
            k+=1
            test_method = create_test_req(testcase)
            test_method.__name__ = 'test_req_%d' % k
            setattr (TestReq, test_method.__name__, test_method)
            
    unittest.main()
