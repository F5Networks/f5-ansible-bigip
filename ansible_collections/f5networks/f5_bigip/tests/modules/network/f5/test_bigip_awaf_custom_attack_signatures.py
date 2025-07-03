# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_custom_attack_signatures import (
    ModuleParameters, ModuleManager, ArgumentSpec
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import (
    set_module_args, exit_json, fail_json
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
            source='/tmp/foo.xml',
            force=True,
            state='import'
        )
        p = ModuleParameters(params=args)

        self.assertTrue(p.force)
        self.assertEqual(p.source, '/tmp/foo.xml')
        self.assertEqual(p.state, 'import')

    def test_module_params_alternate_values(self):
        args = dict(
            dest='/tmp/foo.xml',
            names=['test'],
            state='export'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.names, ['test'])
        self.assertEqual(p.state, 'export')
        self.assertEqual(p.dest, '/tmp/foo.xml')


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.patcher1 = patch('time.sleep')
        self.patcher1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_custom_attack_signatures.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_custom_attack_signatures.F5Client')
        self.m3 = self.p3.start()
        self.m3.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.patcher1.stop()
        # self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_import(self, *args):
        path = os.path.join(fixture_path, "sigfile_2025-6-16_15-56-48943.xml")
        set_module_args(dict(
            source=path,
            state='import'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            # mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'items': [], 'totalItems': 0}},
            {'code': 200, 'contents': {'status': 'COMPLETED', 'result': {'fileSize': 100}}}
        ]
        mm.client.post.return_value = {'code': 200, 'contents': {'id': "1"}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_import_signature_already_exists(self, *args):
        path = os.path.join(fixture_path, "sigfile_2025-6-16_15-56-48943.xml")
        set_module_args(dict(
            source=path,
            state='import'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            # mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'items': [{"name": "test", "id": "-_8EPkjfmhhlNqchgFw74g"}], 'totalItems': 1}},
        ]

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_import_signature_already_exists_with_force(self, *args):
        path = os.path.join(fixture_path, "sigfile_2025-6-16_15-56-48943.xml")
        set_module_args(dict(
            source=path,
            state='import',
            force=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            # mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'items': [{"name": "test", "id": "-_8EPkjfmhhlNqchgFw74g"}], 'totalItems': 1}},
            {'code': 200, 'contents': {'status': 'COMPLETED', 'result': {'fileSize': 100}}}
        ]
        mm.client.post.return_value = {'code': 200, 'contents': {'id': "1"}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_export_signature(self, *args):

        set_module_args(dict(
            names=['test'],
            dest='/tmp/',
            state='export'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            # mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'items': [{"name": "test", "id": "-_8EPkjfmhhlNqchgFw74g"}], 'totalItems': 1}},
            {'code': 200, 'contents': {'status': 'COMPLETED', 'result': {'fileSize': 100}}}
        ]
        mm.client.post.return_value = {'code': 200, 'contents': {'id': "1"}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_export_non_existing_signature(self, *args):

        set_module_args(dict(
            names=['test'],
            dest='/tmp/',
            state='export'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            # mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'items': [], 'totalItems': 0}},
        ]

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            f"Custom Attack Signature Policy '{mm.want.names}' was not found.",
            err.exception.args[0]
        )
