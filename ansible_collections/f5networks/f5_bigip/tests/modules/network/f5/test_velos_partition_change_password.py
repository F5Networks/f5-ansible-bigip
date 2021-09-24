# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.velos_partition_change_password import (
    ModuleParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch, MagicMock
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import set_module_args


fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures')
fixture_data = {}


def load_fixture(name):
    path = os.path.join(fixture_path, name)

    if path in fixture_data:
        return fixture_data[path]

    with open(path) as f:
        data = f.read()

    try:
        data = json.loads(data)
    except Exception:
        pass

    fixture_data[path] = data
    return data


class TestParameters(unittest.TestCase):
    def test_module_parameters(self):
        args = dict(
            user_name='foo',
            old_password='barfoo',
            new_password='abc123@!',
        )

        p = ModuleParameters(params=args)
        assert p.user_name == 'foo'
        assert p.old_password == 'barfoo'
        assert p.new_password == 'abc123@!'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch(
            'ansible_collections.f5networks.f5_bigip.plugins.modules.velos_partition_change_password.F5Client'
        )
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()

    def tearDown(self):
        self.p1.stop()

    def test_change_password_success(self, *args):
        set_module_args(dict(
            user_name='foo',
            old_password='barfoo',
            new_password='abc123@!'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        expected = {'input': [{'old-password': 'barfoo', 'new-password': 'abc123@!', 'confirm-password': 'abc123@!'}]}

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.client.post = Mock(return_value=dict(code=204, contents=''))

        results = mm.exec_module()
        assert results['changed'] is True
        assert mm.client.post.call_args_list[0][0][0] == '/authentication/users/user=foo/config/change-password'
        assert mm.client.post.call_args[1]['data'] == expected

    def test_change_password_fail(self, *args):
        set_module_args(dict(
            user_name='foo',
            old_password='barfoo',
            new_password='abc123@!'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.client.post = Mock(return_value=dict(code=400, contents=load_fixture('password_change_error.json')))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        assert 'Incorrect old password' in str(err.exception)

    def test_change_password_same_password_raises(self, *args):
        set_module_args(dict(
            user_name='foo',
            old_password='barfoo',
            new_password='barfoo'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        assert 'Old and new password cannot be the same.' in str(err.exception)
        assert mm.client.post.call_count == 0
