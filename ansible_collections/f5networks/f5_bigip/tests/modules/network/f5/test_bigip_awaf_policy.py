# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_awaf_policy
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_policy import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import (
    Mock, patch, MagicMock
)
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import (
    set_module_args, fail_json, exit_json, AnsibleExitJson, AnsibleFailJson
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
            policy_in_json='/"invalid", "json"}',
            name='test_foo'
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.policy_in_json()
        self.assertIn("The provided 'policy_in_json' could not be converted into valid json", err.exception.args[0])

        args = dict(
            policy_in_json={"foobar"},
            name='test_foo'
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.policy_in_json()
        self.assertIn("The provided 'policy_in_json' could not be converted into valid json", err.exception.args[0])

        args = dict(
            server_technologies=["foobar"],
            name='test_foo'
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.server_technologies()
        self.assertIn("Invalid entry for server technology: foobar", err.exception.args[0])

    def test_api_parameters(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.file_types)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_policy.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_awaf_policy.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_awaf_policy_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='custom_awaf',
            server_technologies=['AngularJS', 'Apache Struts', 'Apache Tomcat'],
            template='POLICY_TEMPLATE_RAPID_DEPLOYMENT',
            allowed_file_types=[
                dict(name='php', type='explicit'),
                dict(name='jpg', type='explicit')
            ],
            disallowed_file_types=[
                dict(name='js'),
                dict(name='*')
            ],
            case_insensitive=False,
            open_api_files=['https://fake.com/path/to/file.txt'],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertIn('custom_awaf', results['json'])
        self.assertIn('"open-api-files": [{"link": "https://fake.com/path/to/file.txt"}]', results['json'])
        self.assertIn('{"allowed": true, "name": "php", "type": "explicit"}', results['json'])
        self.assertIn('{"allowed": true, "name": "jpg", "type": "explicit"}', results['json'])
        self.assertIn('{"allowed": false, "name": "js"}', results['json'])
        self.assertIn('{"allowed": false, "name": "*"}', results['json'])
        self.assertIn('Apache Tomcat', results['json'])
        self.assertIn('Apache Struts', results['json'])
        self.assertIn('AngularJS', results['json'])

    def test_create_awaf_policy_with_policy_in_json_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        in_json = load_fixture('awaf_big_policy.json')
        set_module_args(dict(
            name='foobar_awaf',
            policy_in_json=in_json,
            server_technologies=['Apache Tomcat'],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertIn('foobar_awaf', results['json'])
        self.assertIn('Apache Tomcat', results['json'])

    def test_modify_awaf_policy_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='custom_awaf',
            language='utf-8',
            server_technologies=['AngularJS'],
            allowed_file_types=[
                dict(name='foo', type='explicit'),
                dict(name='bar', type='explicit'),
            ],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_awaf_policy1.json')),
            dict(code=200, contents=load_fixture('export_awaf_policy1.json'))
        ])
        mm.client.post = Mock(return_value=dict(code=201, contents=load_fixture('start_export_awaf_policy1.json')))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertIn('custom_awaf', results['json'])
        self.assertIn('{"allowed": true, "name": "foo", "type": "explicit"}', results['json'])
        self.assertIn('{"allowed": true, "name": "bar", "type": "explicit"}', results['json'])
        self.assertNotIn('{"serverTechnologyName": "Apache Tomcat"}', results['json'])
        self.assertNotIn('{"serverTechnologyName": "Apache Struts"}', results['json'])
        self.assertIn('{"serverTechnologyName": "AngularJS"}', results['json'])

    def test_modify_awaf_policy_with_policy_in_json_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        in_json = load_fixture('awaf_new_policy.json')
        set_module_args(dict(
            name='foobar_awaf',
            policy_in_json=in_json,
            language='iso-8859-1',
            server_technologies=['AngularJS'],
            allowed_file_types=[
                dict(name='php', type='explicit'),
                dict(name='jpg', type='explicit'),
                dict(name='js', type='explicit'),
            ],
            disallowed_file_types=[
                dict(name='*')
            ],
            force=True,
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_awaf_policy2.json')),
            dict(code=200, contents=load_fixture('export_awaf_policy2.json'))
        ])
        mm.client.post = Mock(return_value=dict(code=201, contents=load_fixture('start_export_awaf_policy2.json')))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertIn('foobar_awaf', results['json'])
        self.assertIn('"applicationLanguage": "iso-8859-1"', results['json'])
        self.assertIn('{"allowed": true, "name": "php", "type": "explicit"}', results['json'])
        self.assertIn('{"allowed": true, "name": "jpg", "type": "explicit"}', results['json'])
        self.assertIn('{"allowed": true, "name": "js", "type": "explicit"}', results['json'])
        self.assertIn('{"allowed": false, "name": "*"}', results['json'])
        self.assertNotIn('{"serverTechnologyName": "Apache Tomcat"}', results['json'])
        self.assertNotIn('{"serverTechnologyName": "Apache Struts"}', results['json'])
        self.assertIn('{"serverTechnologyName": "AngularJS"}', results['json'])

    def test_create_awaf_policy(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='custom_awaf',
            server_technologies=['AngularJS', 'Apache Struts', 'Apache Tomcat'],
            template='POLICY_TEMPLATE_RAPID_DEPLOYMENT',
            pb_learning_mode='disabled',
            allowed_file_types=[
                dict(name='php', type='explicit'),
                dict(name='jpg', type='explicit')
            ],
            disallowed_file_types=[
                dict(name='js'),
                dict(name='*')
            ],
            open_api_files=['https://fake.com/path/to/file.txt'],
            apply_policy=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(side_effect=[
            dict(code=201, contents=load_fixture('start_import_awaf_policy1.json')),
            dict(code=201, contents=load_fixture('start_apply_awaf_policy.json'))
        ])
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('import_awaf_policy1.json')),
            dict(code=200, contents=load_fixture('load_apply_awaf_policy.json'))
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual('POLICY_TEMPLATE_RAPID_DEPLOYMENT', results['template'])
        self.assertEqual('TngPBJ2hfv4tOPTKQAvTGw', results['policy_id'])
        self.assertEqual('disabled', results['pb_learning_mode'])
        self.assertListEqual(['https://fake.com/path/to/file.txt'], results['open_api_files'])
        self.assertListEqual(['AngularJS', 'Apache Struts', 'Apache Tomcat'], results['server_technologies'])
        self.assertListEqual(
            [{'name': 'php', 'type': 'explicit'}, {'name': 'jpg', 'type': 'explicit'}], results['allowed_file_types']
        )
        self.assertListEqual(
            [{'name': 'js'}, {'name': '*'}], results['disallowed_file_types']
        )

    def test_create_awaf_policy_idempotent_check(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='custom_awaf',
            server_technologies=['AngularJS', 'Apache Struts', 'Apache Tomcat'],
            template='POLICY_TEMPLATE_RAPID_DEPLOYMENT',
            pb_learning_mode='manual',
            allowed_file_types=[
                dict(name='php', type='explicit'),
                dict(name='jpg', type='explicit')
            ],
            disallowed_file_types=[
                dict(name='js'),
                dict(name='*')
            ],
            apply_policy=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_awaf_policy1.json')),
            dict(code=200, contents=load_fixture('export_awaf_policy1.json')),

        ])
        mm.client.post = Mock(return_value=dict(code=201, contents=load_fixture('start_export_awaf_policy1.json')))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_create_awaf_policy_with_policy_in_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        in_json = load_fixture('awaf_big_policy.json')
        set_module_args(dict(
            name='foobar_awaf',
            policy_in_json=in_json,
            server_technologies=['Apache Tomcat']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=201, contents=load_fixture('start_import_awaf_policy2.json')))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('import_awaf_policy2.json')))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual('mqpqW0IAYvBswslAuleC1A', results['policy_id'])
        self.assertEqual('utf-8', results['language'])
        self.assertEqual('blocking', results['enforcement_mode'])
        self.assertEqual('security', results['type'])
        self.assertEqual('mqpqW0IAYvBswslAuleC1A', results['policy_id'])
        self.assertFalse(results['enable_passive_mode'])
        self.assertFalse(results['protocol_independent'])
        self.assertFalse(results['case_insensitive'])
        self.assertFalse(results['enable_passive_mode'])
        self.assertListEqual(['Apache Tomcat'], results['server_technologies'])

    def test_create_awaf_policy_with_policy_in_json_idempotent_check(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        in_json = load_fixture('awaf_big_policy.json')
        set_module_args(dict(
            name='foobar_awaf',
            policy_in_json=in_json,
            server_technologies=['Apache Tomcat']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_awaf_policy2.json')),
            dict(code=200, contents=load_fixture('export_awaf_policy2.json'))
        ])
        mm.client.post = Mock(return_value=dict(code=201, contents=load_fixture('start_export_awaf_policy2.json')))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_modify_awaf_policy(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='custom_awaf',
            language='utf-8',
            allowed_file_types=[
                dict(name='foo', type='explicit'),
                dict(name='bar', type='explicit'),
            ],
            apply_policy=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_awaf_policy1.json')),
            dict(code=200, contents=load_fixture('export_awaf_policy1.json')),
            dict(code=200, contents=load_fixture('import_awaf_policy1_modified.json')),
            dict(code=200, contents=load_fixture('load_apply_awaf_policy.json'))

        ])
        mm.client.post = Mock(side_effect=[
            dict(code=201, contents=load_fixture('start_export_awaf_policy1.json')),
            dict(code=201, contents=load_fixture('start_import_awaf_policy1_modified.json')),
            dict(code=201, contents=load_fixture('start_apply_awaf_policy.json'))
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual('utf-8', results['language'])
        self.assertEqual('TngPBJ2hfv4tOPTKQAvTGw', results['policy_id'])
        self.assertListEqual(
            [{'name': 'foo', 'type': 'explicit'}, {'name': 'bar', 'type': 'explicit'}], results['allowed_file_types']
        )

    def test_modify_awaf_policy_with_policy_id(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            policy_id='TngPBJ2hfv4tOPTKQAvTGw',
            language='utf-8',
            allowed_file_types=[
                dict(name='foo', type='explicit'),
                dict(name='bar', type='explicit'),
            ],
            apply_policy=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_awaf_policy_by_id.json')),
            dict(code=200, contents=load_fixture('export_awaf_policy1.json')),
            dict(code=200, contents=load_fixture('import_awaf_policy1_modified.json')),
            dict(code=200, contents=load_fixture('load_apply_awaf_policy.json'))

        ])
        mm.client.post = Mock(side_effect=[
            dict(code=201, contents=load_fixture('start_export_awaf_policy1.json')),
            dict(code=201, contents=load_fixture('start_import_awaf_policy1_modified.json')),
            dict(code=201, contents=load_fixture('start_apply_awaf_policy.json'))
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual('utf-8', results['language'])
        self.assertEqual('TngPBJ2hfv4tOPTKQAvTGw', results['policy_id'])
        self.assertListEqual(
            [{'name': 'foo', 'type': 'explicit'}, {'name': 'bar', 'type': 'explicit'}], results['allowed_file_types']
        )

    def test_modify_awaf_policy_with_policy_in_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        in_json = load_fixture('awaf_new_policy.json')
        set_module_args(dict(
            name='foobar_awaf',
            policy_in_json=in_json,
            server_technologies=['AngularJS'],
            allowed_file_types=[
                dict(name='php', type='explicit'),
                dict(name='jpg', type='explicit'),
                dict(name='js', type='explicit'),
            ],
            disallowed_file_types=[
                dict(name='*')
            ],
            apply_policy=True,
            force=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_awaf_policy2.json')),
            dict(code=200, contents=load_fixture('export_awaf_policy2.json')),
            dict(code=200, contents=load_fixture('import_awaf_policy2_modified.json')),
            dict(code=200, contents=load_fixture('load_apply_awaf_policy.json'))
        ])
        mm.client.post = Mock(side_effect=[
            dict(code=201, contents=load_fixture('start_export_awaf_policy2.json')),
            dict(code=201, contents=load_fixture('start_import_awaf_policy2_modified.json')),
            dict(code=201, contents=load_fixture('start_apply_awaf_policy.json'))
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertIn('this is a test to check IPI behaviour', results['description'])
        self.assertEqual('mqpqW0IAYvBswslAuleC1A', results['policy_id'])
        self.assertListEqual(['AngularJS'], results['server_technologies'])
        self.assertListEqual(
            [{'name': 'php', 'type': 'explicit'}, {'name': 'jpg', 'type': 'explicit'},
             {'name': 'js', 'type': 'explicit'}], results['allowed_file_types']
        )
        self.assertListEqual([{'name': '*'}], results['disallowed_file_types'])

    def test_delete_awaf_policy(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='foobar_awaf',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_delete_awaf_policy_error_response(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='foobar_awaf',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=True)
        mm.client.delete = Mock(return_value=dict(code=404, contents='not found'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_create_awaf_policy_missing_template(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='custom_awaf',
            server_technologies=['AngularJS', 'Apache Struts', 'Apache Tomcat'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn("The 'template' parameter must be provided when creating new policy", err.exception.args[0])

    def test_create_awaf_policy_missing_server_tech(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='custom_awaf',
            template='POLICY_TEMPLATE_RAPID_DEPLOYMENT',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "The 'server_technologies' parameter must be provided when creating new policy", err.exception.args[0]
        )

    def test_create_awaf_policy_policy_id_raises(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            policy_id='123456'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "The 'name' and 'partition' parameters must be used when creating a new policy", err.exception.args[0]
        )

    @patch.object(bigip_awaf_policy, 'Connection')
    @patch.object(bigip_awaf_policy.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_awaf_policy.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_awaf_policy, 'Connection')
    @patch.object(bigip_awaf_policy.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_awaf_policy.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name="foobar",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[
            dict(code=404), dict(code=400, contents='server error'),
            dict(code=200, contents={})
        ])

        mm.client.post = Mock(side_effect=[
            dict(code=401, contents='access denied'),
            dict(code=200, contents=dict(id='foobar')),
            dict(code=403, contents='forbidden'),
            dict(code=500, contents='path error'),
        ])

        res1 = mm.exists()
        self.assertFalse(res1)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

        res2 = mm.exists()
        self.assertFalse(res2)

        mm.exists = Mock(side_effect=[False, True])
        res3 = mm.absent()
        self.assertFalse(res3)

        with self.assertRaises(F5ModuleError) as err2:
            mm.remove_from_device = Mock(return_value=True)
            mm.remove()
        self.assertIn('Failed to delete the resource.', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.read_current_from_device()
        self.assertIn('access denied', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.wait_for_task = Mock(return_value={})
            mm.read_current_from_device()
        self.assertIn('Failed to read exported aWAF policy', err3.exception.args[0])

        mm._update_changed_options = Mock(return_value=False)
        mm.read_current_from_device = Mock(return_value=dict())
        self.assertFalse(mm.update())

        with self.assertRaises(F5ModuleError) as err4:
            mm.import_policy('foobar')
        self.assertIn('forbidden', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            mm.apply_policy()
        self.assertIn('path error', err5.exception.args[0])

        mm.client.get = Mock(side_effect=[
            dict(code=404), dict(code=400, contents='server error')
        ])

        set_module_args(dict(
            policy_id="123456",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )

        mm = ModuleManager(module=module)

        res4 = mm.exists()
        self.assertFalse(res4)

        with self.assertRaises(F5ModuleError) as err6:
            mm.exists()
        self.assertIn('server error', err6.exception.args[0])

    def test_wait_for_task(self):
        set_module_args(dict(
            name="foobar",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[
            dict(code=500, contents='server error'),
            dict(code=200, contents=dict(status='FAILURE', result={'message': 'foo export failure'})),
            dict(code=200, contents=dict(status='FAILURE', result={'message': 'foo apply failure'})),
            dict(code=200, contents=dict(status='FAILURE', result={'message': 'foo import failure'})),
            dict(code=200, contents=dict(status='STARTING')),
            dict(code=200, contents=dict(status='COMPLETED'))

        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.wait_for_task('123456')
        self.assertIn('server error', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            mm.wait_for_task('123456', export=True)
        self.assertIn('foo export failure', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            mm.wait_for_task('123456', apply=True)
        self.assertIn('foo apply failure', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            mm.wait_for_task('123456')
        self.assertIn('foo import failure', err.exception.args[0])

        res = mm.wait_for_task('123456', apply=True)
        self.assertTrue(res)
