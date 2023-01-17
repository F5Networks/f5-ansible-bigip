# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_lx_package
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_lx_package import (
    Parameters, ArgumentSpec, ModuleManager
)

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch, MagicMock
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
            package='MyApp-0.1.0-0001.noarch.rpm',
            state='present'
        )
        p = Parameters(params=args)
        self.assertEqual(p.package, 'MyApp-0.1.0-0001.noarch.rpm')


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_lx_package.send_teem')
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_lx_package.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.m3 = self.p3.start()
        self.m3.return_value = MagicMock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_upload_rpm_package(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            package=package_name,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(side_effect=[False, True])
        mm.wait_for_task = Mock(return_value=dict(status='FINISHED'))

        mm.client.post.side_effect = [
            {'code': 201, 'contents': {'commandResult': ''}},
            {'code': 202, 'contents': {'selfLink': '/task/path'}},
            {'code': 200},
            {'code': 200},
        ]

        results = mm.exec_module()

        self.assertEqual(mm.client.post.call_count, 4)
        self.assertTrue(results['changed'])

    def test_remove_rpm_package(self, *args):
        package_file = 'MyApp-0.1.0-0001.noarch.rpm'
        package_name = os.path.join(fixture_path, package_file)

        set_module_args(dict(
            package=package_name,
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        module.run_command = Mock(return_value=(None, None, None))
        mm = ModuleManager(module=module)

        mm.client.post.return_value = {'code': 202, 'contents': {'selfLink': '/task/path'}}
        mm.client.get.side_effect = [
            dict(code=200, contents={'status': 'FINISHED', 'queryResponse': [{'packageName': 'MyApp-0.1.0-0001.noarch.rpm'}]}),
            dict(code=200, contents={'status': 'FINISHED'}),
            dict(code=200, contents={'status': 'FINISHED', 'queryResponse': [{'packageName': ''}]}),
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.get.call_count, 3)

    @patch.object(bigip_lx_package, 'Connection')
    @patch.object(bigip_lx_package.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            package='foobar'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_lx_package.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_lx_package, 'Connection')
    @patch.object(bigip_lx_package.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            package='foobar'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_lx_package.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
