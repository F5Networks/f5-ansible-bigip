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

    def test_export_idempotent(self, *args):
        set_module_args(dict(
            names=['test'],
            dest='/tmp/',
            state='export'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        # First call returns signatures exist
        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'items': [{"name": "test", "id": "-_8EPkjfmhhlNqchgFw74g"}], 'totalItems': 1}},
            {'code': 200, 'contents': {'status': 'COMPLETED', 'result': {'fileSize': 100}}}
        ]
        mm.client.post.return_value = {'code': 200, 'contents': {'id': "1"}}

        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_import_api_error_on_signature_check(self, *args):
        path = os.path.join(fixture_path, "sigfile_2025-6-16_15-56-48943.xml")
        set_module_args(dict(
            source=path,
            state='import'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        mm.client.get.return_value = {'code': 500, 'contents': 'API error'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('API error', err.exception.args[0])

    def test_import_task_wait_failure(self, *args):
        path = os.path.join(fixture_path, "sigfile_2025-6-16_15-56-48943.xml")
        set_module_args(dict(
            source=path,
            state='import'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'items': [], 'totalItems': 0}},
            {'code': 200, 'contents': {'status': 'FAILURE'}}
        ]
        mm.client.post.return_value = {'code': 200, 'contents': {'id': "1"}}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to import Custom Signatures Attack file', err.exception.args[0])

    def test_export_api_error_on_export_task(self, *args):
        set_module_args(dict(
            names=['test'],
            dest='/tmp/',
            state='export'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        mm.client.get.return_value = {'code': 200, 'contents': {'items': [{"name": "test", "id": "-_8EPkjfmhhlNqchgFw74g"}], 'totalItems': 1}}
        mm.client.post.return_value = {'code': 500, 'contents': 'export failed'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('export failed', err.exception.args[0])

    def test_export_task_wait_failure(self, *args):
        set_module_args(dict(
            names=['test'],
            dest='/tmp/',
            state='export'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'items': [{"name": "test", "id": "-_8EPkjfmhhlNqchgFw74g"}], 'totalItems': 1}},
            {'code': 200, 'contents': {'status': 'FAILURE'}}
        ]
        mm.client.post.return_value = {'code': 200, 'contents': {'id': "1"}}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to import Custom Signatures Attack file', err.exception.args[0])

    def test_signature_exists_api_error(self, *args):
        set_module_args(dict(
            names=['test'],
            dest='/tmp/',
            state='export'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        mm.client.get.return_value = {'code': 500, 'contents': 'API error on signature check'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('API error on signature check', err.exception.args[0])

    def test_signature_not_found_404(self, *args):
        set_module_args(dict(
            names=['nonexistent'],
            dest='/tmp/',
            state='export'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        mm.client.get.return_value = {'code': 404}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            f"Custom Attack Signature Policy '{mm.want.names}' was not found.",
            err.exception.args[0]
        )

    def test_import_force_overwrites_existing(self, *args):
        path = os.path.join(fixture_path, "sigfile_2025-6-16_15-56-48943.xml")
        set_module_args(dict(
            source=path,
            state='import',
            force=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        # Signatures already exist but force=True
        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'items': [{"name": "test", "id": "-_8EPkjfmhhlNqchgFw74g"}], 'totalItems': 1}},
            {'code': 200, 'contents': {'status': 'COMPLETED', 'result': {'fileSize': 100}}}
        ]
        mm.client.post.return_value = {'code': 200, 'contents': {'id': "1"}}

        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_import_no_force_skips_existing(self, *args):
        path = os.path.join(fixture_path, "sigfile_2025-6-16_15-56-48943.xml")
        set_module_args(dict(
            source=path,
            state='import',
            force=False
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        # Signatures already exist and force=False
        mm.client.get.return_value = {'code': 200, 'contents': {'items': [{"name": "test", "id": "-_8EPkjfmhhlNqchgFw74g"}], 'totalItems': 1}}

        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_partial_signatures_mismatch(self, *args):
        set_module_args(dict(
            names=['test1', 'test2'],
            dest='/tmp/',
            state='export'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        # Only one of two requested signatures exists
        mm.client.get.return_value = {'code': 200, 'contents': {'items': [{"name": "test1", "id": "id1"}], 'totalItems': 1}}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            f"Custom Attack Signature Policy '{mm.want.names}' was not found.",
            err.exception.args[0]
        )

    def test_main_function_success(self, *args):
        with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_custom_attack_signatures.Connection',
                   create=True) as mock_connection:
            path = os.path.join(fixture_path, "sigfile_2025-6-16_15-56-48943.xml")
            set_module_args(dict(
                source=path,
                state='import'
            ))

            mock_conn_instance = Mock()
            mock_connection.return_value = mock_conn_instance

            with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_custom_attack_signatures.ModuleManager') as mm_mock:
                mm_instance = Mock()
                mm_mock.return_value = mm_instance
                mm_instance.exec_module.return_value = {'changed': True, 'state': 'import'}

                with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_custom_attack_signatures.AnsibleModule') as module_mock:
                    module_instance = Mock()
                    module_mock.return_value = module_instance

                    from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_custom_attack_signatures import main
                    main()

                    module_instance.exit_json.assert_called_once()

    def test_main_function_failed(self, *args):
        with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_custom_attack_signatures.Connection',
                   create=True) as mock_connection:
            set_module_args(dict(
                names=['test'],
                dest='/tmp/',
                state='export'
            ))

            mock_conn_instance = Mock()
            mock_connection.return_value = mock_conn_instance

            with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_custom_attack_signatures.ModuleManager') as mm_mock:
                mm_instance = Mock()
                mm_mock.return_value = mm_instance
                mm_instance.exec_module.side_effect = F5ModuleError('Test error')

                with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_custom_attack_signatures.AnsibleModule') as module_mock:
                    module_instance = Mock()
                    module_mock.return_value = module_instance

                    from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_custom_attack_signatures import main
                    main()

                    module_instance.fail_json.assert_called_once()

    def test_import_post_request_error(self, *args):
        path = os.path.join(fixture_path, "sigfile_2025-6-16_15-56-48943.xml")
        set_module_args(dict(
            source=path,
            state='import'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        # Signatures don't exist (OK to import)
        mm.client.get.return_value = {'code': 200, 'contents': {'items': [], 'totalItems': 0}}
        # POST request fails during import task
        mm.client.post.return_value = {'code': 500, 'contents': 'import post error'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('import post error', err.exception.args[0])

    def test_export_empty_results_list(self, *args):
        set_module_args(dict(
            names=['test'],
            dest='/tmp/',
            state='export'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        # Return empty items list for signature search
        mm.client.get.return_value = {'code': 200, 'contents': {'items': [], 'totalItems': 0}}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('was not found', err.exception.args[0])

    def test_export_task_wait_api_error(self, *args):
        set_module_args(dict(
            names=['test'],
            dest='/tmp/',
            state='export'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        # Signature exists
        # POST to export returns success
        # GET on task wait returns error
        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'items': [{"name": "test", "id": "-_8EPkjfmhhlNqchgFw74g"}], 'totalItems': 1}},
            {'code': 500, 'contents': 'task api error'}
        ]
        mm.client.post.return_value = {'code': 200, 'contents': {'id': "task-123"}}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('task api error', err.exception.args[0])
