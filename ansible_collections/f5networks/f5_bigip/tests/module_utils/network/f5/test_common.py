# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import ansible_collections.f5networks.f5_bigip.plugins.module_utils.common as comm
from unittest import TestCase
from unittest.mock import MagicMock, patch


class TestFunctions(TestCase):
    def test_process_json_raises(self):
        comm.JINA2_IMPORT_ERROR = ImportError('Something bad happened during j2 import.')
        with self.assertRaises(comm.F5ModuleError) as err:
            comm.process_json('foodata', 'footemplate')

        assert 'jinja2 package must be installed to use this collection' in str(err.exception)
        comm.JINA2_IMPORT_ERROR = None

    def test_fq_name(self):
        res1 = comm.fq_name('Foo', '100',)
        assert res1 == '/Foo/100'

        res2 = comm.fq_name('Foo', '1.1')
        assert res2 == '/Foo/1.1'

        res3 = comm.fq_name('Foo', '100', 'Bar')
        assert res3 == '/Foo/Bar/100'

        res4 = comm.fq_name('Foo', '/Baz/Resource', 'Bar')
        assert res4 == '/Baz/Bar/Resource'

        res5 = comm.fq_name('Foo', 'Resource', 'Bar')
        assert res5 == '/Foo/Bar/Resource'

        res6 = comm.fq_name('Foo', None)
        assert res6 is None

    def test_to_commands(self):
        fake_module = MagicMock()
        result = comm.to_commands(fake_module, ['command1', 'command2'])
        assert result == [
            {'command': 'command1', 'prompt': None, 'answer': None},
            {'command': 'command2', 'prompt': None, 'answer': None}
        ]

    @patch('ansible_collections.f5networks.f5_bigip.plugins.module_utils.common.exec_command', new_callable=MagicMock())
    def test_run_commands(self, patched):
        fake_module = MagicMock()
        command = ['command1']
        patched.side_effect = [(0, b'some command response', None), (1, None, b'bad command')]
        result = comm.run_commands(fake_module, command)

        with self.assertRaises(comm.F5ModuleError) as err:
            comm.run_commands(fake_module, command)

        assert result == ['some command response']
        assert 'bad command' in str(err.exception)

    def test_flatten_boolean(self):
        true = 'enabled'
        false = 'disabled'

        res1 = comm.flatten_boolean(true)
        res2 = comm.flatten_boolean(false)
        res3 = comm.flatten_boolean(None)

        assert res1 == 'yes'
        assert res2 == 'no'
        assert res3 is None

    def test_merge_two_dics(self):
        first = dict(foo=1, bar=2)
        second = dict(baz=3)
        result = comm.merge_two_dicts(first, second)

        assert result == {'foo': 1, 'bar': 2, 'baz': 3}

    def test_transform_name(self):
        res1 = comm.transform_name('/this%isaname')
        res2 = comm.transform_name('Common', 'Common/Foo')
        res3 = comm.transform_name('Common', '/Common/Foo')
        res4 = comm.transform_name('Common', 'Common/Foo', 'Baz')

        with self.assertRaises(comm.F5ModuleError) as err:
            comm.transform_name(name='/Common/foo', sub_path='Baz')

        assert res1 == '~this%isaname'
        assert res2 == '~Common~Foo'
        assert res3 == '~Common~Foo'
        assert res4 == '~Common~Baz~Foo'
        assert 'When giving the subPath component include partition as well.' in str(err.exception)
