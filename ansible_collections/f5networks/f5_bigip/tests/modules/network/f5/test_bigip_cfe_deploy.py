# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_cfe_deploy
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_cfe_deploy import (
    Parameters, ArgumentSpec, ModuleManager, ModuleParameters
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
            content=dict(param1='foo', param2='bar'),
        )
        p = Parameters(params=args)
        self.assertEqual(p.content, dict(param1='foo', param2='bar'))

    def test_module_parameters_content(self):
        args1 = dict(
            content='{"param1":"foo","param2":"bar"}'
        )
        args2 = dict()
        p1 = ModuleParameters(params=args1)
        p2 = ModuleParameters(params=args2)
        self.assertEqual(p1.content, dict(param1='foo', param2='bar'))
        self.assertEqual(p2.content, None)


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_cfe_deploy.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_cfe_deploy.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_upsert_cfe_declaration(self, *args):
        declaration = load_fixture('failover_declaration.json')
        set_module_args(dict(
            content=declaration,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.post.return_value = {'code': 200, 'contents': {'message': 'success'}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_upsert_cfe_response_status_failure(self, *args):
        declaration = load_fixture('failover_declaration.json')
        set_module_args(dict(
            content=declaration,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.post.return_value = {
            'code': 503,
            'contents': 'service not available'
        }

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_upsert_cfe_return_false(self, *args):
        declaration = load_fixture('failover_declaration.json')
        set_module_args(dict(
            content=declaration,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.post.return_value = {
            'code': 200,
            'contents': {
                'message': 'failed'
            }
        }

        results = mm.exec_module()
        self.assertFalse(results['changed'])

    @patch.object(bigip_cfe_deploy, 'Connection')
    @patch.object(bigip_cfe_deploy.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False})
                  )
    def test_main_function_success(self, *args):
        set_module_args(dict(
            content='declaration'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_cfe_deploy.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_cfe_deploy, 'Connection')
    @patch.object(bigip_cfe_deploy.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            content='declaration'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_cfe_deploy.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
