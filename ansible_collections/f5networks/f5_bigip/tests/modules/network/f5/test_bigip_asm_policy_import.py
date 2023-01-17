# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_asm_policy_import
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_asm_policy_import import (
    ModuleParameters, ModuleManager, ArgumentSpec
)

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import (
    set_module_args, AnsibleExitJson, AnsibleFailJson, exit_json, fail_json
)


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
            name='fake_policy',
            state='present',
            source='/var/fake/fake.xml'
        )

        p = ModuleParameters(params=args)
        self.assertEqual(p.name, 'fake_policy')
        self.assertEqual(p.source, '/var/fake/fake.xml')


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.policy = os.path.join(fixture_path, 'fake_policy.xml')
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_asm_policy_import.module_provisioned')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_asm_policy_import.send_teem')
        self.m3 = self.p3.start()
        self.m3.return_value = True
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_asm_policy_import.F5Client')
        self.m4 = self.p4.start()
        self.m4.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()
        self.mock_module_helper.stop()

    def test_import_from_file(self, *args):
        set_module_args(dict(
            name='fake_policy',
            source=self.policy
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'items': [{'name': 'different_policy'}]}},
            {'code': 200, 'contents': {'status': 'IN PROGRESS'}},
            {'code': 200, 'contents': {'status': 'COMPLETED'}}
        ]
        mm.client.post.return_value = {'code': 200, 'contents': {'id': 1}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['name'], 'fake_policy')
        self.assertEqual(results['source'], self.policy)

    def test_import_from_file_inline(self, *args):
        set_module_args(dict(
            name='fake_policy',
            force='yes',
            inline='yes'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.wait_for_task = Mock(return_value=True)

        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'items': [{'name': 'fake_policy', 'partition': 'Common'}]}},
            {'code': 200, 'contents': {'items': [{'name': 'fake_policy', 'partition': 'Common'}]}},
            {'code': 200, 'contents': {'items': [{'name': 'fake_policy', 'partition': 'Common', 'selfLink': 'policyLink'}]}}
        ]
        mm.client.post.return_value = {'code': 200, 'contents': {'id': 1}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['name'], 'fake_policy')

    @patch.object(bigip_asm_policy_import, 'Connection')
    @patch.object(bigip_asm_policy_import.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False})
                  )
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='fake_policy',
            force='yes',
            inline='yes'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_asm_policy_import.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_asm_policy_import, 'Connection')
    @patch.object(bigip_asm_policy_import.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='fake_policy',
            force='yes',
            inline='yes'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_asm_policy_import.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
