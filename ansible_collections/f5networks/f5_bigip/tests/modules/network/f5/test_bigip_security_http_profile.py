# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_security_http_profile
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_http_profile import (
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
            name='test_http_profile',
            parent='foo_bar',
            description='this is a foo',
            evasion_techniques=dict(alarm=False, block=True),
            file_type=dict(
                alarm=False,
                block=True,
                allowed=['BAZ'],
                disallowed=['BAR']
            ),
            http_protocol_checks=dict(
                alarm=False,
                block=True,
                bad_host_header='yes',
                bad_version='on',
                body_in_get_head=True,
                chunked_with_content_length=False,
                content_length_is_positive='true',
                header_name_without_value='false',
                high_ascii_in_headers='true',
                host_header_is_ip=False,
                maximum_headers=100,
                null_in_body=True,
                null_in_headers=False,
                post_with_zero_length=True,
                several_content_length=False,
                unparsable_content=False
            ),
            method=dict(
                alarm=False,
                block=True,
                allowed_methods=['GET']
            ),
            header=dict(
                alarm=False,
                block=True,
                mandatory_headers=['authorization', 'cookie']
            ),
            length=dict(
                alarm=True,
                block=False,
                query_string=20,
                post_data=0,
                request=2048,
                uri=512
            ),
            response=dict(
                type='custom',
                body='abcd12345',
                header='HEADER:FOO',
                url='https://you-are-banned.net',
            )
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.parent, '/Common/foo_bar')
        self.assertEqual(p.description, 'this is a foo')
        self.assertEqual(p.evasion_alarm, 'disabled')
        self.assertEqual(p.evasion_block, 'enabled')
        self.assertEqual(p.file_alarm, 'disabled')
        self.assertEqual(p.file_block, 'enabled')
        self.assertListEqual(p.files_allowed, ['BAZ'])
        self.assertListEqual(p.files_disallowed, ['BAR'])
        self.assertEqual(p.http_check_alarm, 'disabled')
        self.assertEqual(p.http_check_block, 'enabled')
        self.assertEqual(p.http_check_bad_host_header, 'enabled')
        self.assertEqual(p.http_check_bad_version, 'enabled')
        self.assertEqual(p.http_check_body_in_get, 'enabled')
        self.assertEqual(p.http_check_chunk_with_content_length, 'disabled')
        self.assertEqual(p.http_check_content_length_positive, 'enabled')
        self.assertEqual(p.http_check_header_no_value, 'disabled')
        self.assertEqual(p.http_check_high_ascii, 'enabled')
        self.assertEqual(p.http_check_header_is_ip, 'disabled')
        self.assertEqual(p.http_check_max_headers, '100')
        self.assertEqual(p.http_check_null_in_body, 'enabled')
        self.assertEqual(p.http_check_null_in_headers, 'disabled')
        self.assertEqual(p.http_check_post_with_zero_length, 'enabled')
        self.assertEqual(p.http_check_several_content_length, 'disabled')
        self.assertEqual(p.http_check_unparsable_content, 'disabled')
        self.assertEqual(p.method_alarm, 'disabled')
        self.assertEqual(p.method_block, 'enabled')
        self.assertListEqual(p.allowed_methods, ['GET'])
        self.assertEqual(p.header_alarm, 'disabled')
        self.assertEqual(p.header_block, 'enabled')
        self.assertListEqual(p.mandatory_headers, ['authorization', 'cookie'])
        self.assertEqual(p.length_alarm, 'enabled')
        self.assertEqual(p.length_block, 'disabled')
        self.assertEqual(p.length_query_string, '20')
        self.assertEqual(p.length_post_data, 'any')
        self.assertEqual(p.length_request, '2048')
        self.assertEqual(p.length_uri, '512')
        self.assertEqual(p.response_type, 'custom')
        self.assertEqual(p.response_body, 'abcd12345')
        self.assertEqual(p.response_headers, 'HEADER:FOO')
        self.assertEqual(p.response_url, 'https://you-are-banned.net')

    def test_invalid_rate_raises(self):
        args = dict(http_protocol_checks=dict(maximum_headers=200))

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.http_check_max_headers()

        self.assertIn('The maximum headers value value must be in range of 1 - 150', err.exception.args[0])

    def test_api_parameters(self):
        args = load_fixture('load_http_security_profile.json')

        p = ApiParameters(params=args)

        self.assertEqual(p.parent, '/Common/http_security')
        self.assertEqual(p.description, 'this is a test profile')
        self.assertEqual(p.evasion_alarm, 'disabled')
        self.assertEqual(p.evasion_block, 'enabled')
        self.assertEqual(p.file_alarm, 'disabled')
        self.assertEqual(p.file_block, 'disabled')
        self.assertListEqual(p.files_allowed, ['ZIP', 'JS', 'JSON'])
        self.assertEqual(p.http_check_alarm, 'enabled')
        self.assertEqual(p.http_check_block, 'disabled')
        self.assertEqual(p.http_check_bad_host_header, 'enabled')
        self.assertEqual(p.http_check_bad_version, 'enabled')
        self.assertEqual(p.http_check_body_in_get, 'enabled')
        self.assertEqual(p.http_check_chunk_with_content_length, 'enabled')
        self.assertEqual(p.http_check_content_length_positive, 'enabled')
        self.assertEqual(p.http_check_header_no_value, 'enabled')
        self.assertEqual(p.http_check_high_ascii, 'enabled')
        self.assertEqual(p.http_check_header_is_ip, 'disabled')
        self.assertEqual(p.http_check_max_headers, '20')
        self.assertEqual(p.http_check_null_in_body, 'disabled')
        self.assertEqual(p.http_check_null_in_headers, 'enabled')
        self.assertEqual(p.http_check_post_with_zero_length, 'disabled')
        self.assertEqual(p.http_check_several_content_length, 'enabled')
        self.assertEqual(p.http_check_unparsable_content, 'enabled')
        self.assertEqual(p.method_alarm, 'enabled')
        self.assertEqual(p.method_block, 'enabled')
        self.assertListEqual(p.allowed_methods, ['GET', 'POST', 'PATCH'])
        self.assertEqual(p.header_alarm, 'disabled')
        self.assertEqual(p.header_block, 'disabled')
        self.assertListEqual(p.mandatory_headers, ['authorization', 'cookie'])
        self.assertEqual(p.length_alarm, 'enabled')
        self.assertEqual(p.length_block, 'disabled')
        self.assertEqual(p.length_query_string, '1024')
        self.assertEqual(p.length_post_data, 'any')
        self.assertEqual(p.length_request, '2048')
        self.assertEqual(p.length_uri, '512')
        self.assertEqual(p.response_type, 'redirect')
        self.assertEqual(p.response_url, 'https://you-are-banned.net')

    def test_module_parameters_none(self):
        args = dict(name='test_http_profile')

        p = ModuleParameters(params=args)

        self.assertIsNone(p.parent)
        self.assertIsNone(p.description)
        self.assertIsNone(p.evasion_alarm)
        self.assertIsNone(p.evasion_block)
        self.assertIsNone(p.file_alarm)
        self.assertIsNone(p.file_block)
        self.assertIsNone(p.files_allowed)
        self.assertIsNone(p.files_disallowed)
        self.assertIsNone(p.http_check_alarm)
        self.assertIsNone(p.http_check_block)
        self.assertIsNone(p.http_check_bad_host_header)
        self.assertIsNone(p.http_check_bad_version)
        self.assertIsNone(p.http_check_body_in_get)
        self.assertIsNone(p.http_check_chunk_with_content_length)
        self.assertIsNone(p.http_check_content_length_positive)
        self.assertIsNone(p.http_check_header_no_value)
        self.assertIsNone(p.http_check_high_ascii)
        self.assertIsNone(p.http_check_header_is_ip)
        self.assertIsNone(p.http_check_max_headers)
        self.assertIsNone(p.http_check_null_in_body)
        self.assertIsNone(p.http_check_null_in_headers)
        self.assertIsNone(p.http_check_post_with_zero_length)
        self.assertIsNone(p.http_check_several_content_length)
        self.assertIsNone(p.http_check_unparsable_content)
        self.assertIsNone(p.method_alarm)
        self.assertIsNone(p.method_block)
        self.assertIsNone(p.allowed_methods)
        self.assertIsNone(p.header_alarm)
        self.assertIsNone(p.header_block)
        self.assertIsNone(p.mandatory_headers)
        self.assertIsNone(p.length_alarm)
        self.assertIsNone(p.length_block)
        self.assertIsNone(p.length_query_string)
        self.assertIsNone(p.length_post_data)
        self.assertIsNone(p.length_request)
        self.assertIsNone(p.length_uri)
        self.assertIsNone(p.response_type)
        self.assertIsNone(p.response_body)
        self.assertIsNone(p.response_headers)
        self.assertIsNone(p.response_url)

    def test_api_parameters_none(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.parent)
        self.assertIsNone(p.description)
        self.assertIsNone(p.evasion_alarm)
        self.assertIsNone(p.evasion_block)
        self.assertIsNone(p.file_alarm)
        self.assertIsNone(p.file_block)
        self.assertIsNone(p.files_allowed)
        self.assertIsNone(p.files_disallowed)
        self.assertIsNone(p.http_check_alarm)
        self.assertIsNone(p.http_check_block)
        self.assertIsNone(p.http_check_bad_host_header)
        self.assertIsNone(p.http_check_bad_version)
        self.assertIsNone(p.http_check_body_in_get)
        self.assertIsNone(p.http_check_chunk_with_content_length)
        self.assertIsNone(p.http_check_content_length_positive)
        self.assertIsNone(p.http_check_header_no_value)
        self.assertIsNone(p.http_check_high_ascii)
        self.assertIsNone(p.http_check_header_is_ip)
        self.assertIsNone(p.http_check_max_headers)
        self.assertIsNone(p.http_check_null_in_body)
        self.assertIsNone(p.http_check_null_in_headers)
        self.assertIsNone(p.http_check_post_with_zero_length)
        self.assertIsNone(p.http_check_several_content_length)
        self.assertIsNone(p.http_check_unparsable_content)
        self.assertIsNone(p.method_alarm)
        self.assertIsNone(p.method_block)
        self.assertIsNone(p.allowed_methods)
        self.assertIsNone(p.header_alarm)
        self.assertIsNone(p.header_block)
        self.assertIsNone(p.mandatory_headers)
        self.assertIsNone(p.length_alarm)
        self.assertIsNone(p.length_block)
        self.assertIsNone(p.length_query_string)
        self.assertIsNone(p.length_post_data)
        self.assertIsNone(p.length_request)
        self.assertIsNone(p.length_uri)
        self.assertIsNone(p.response_type)
        self.assertIsNone(p.response_body)
        self.assertIsNone(p.response_headers)
        self.assertIsNone(p.response_url)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_http_profile.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_http_profile.F5Client')
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

    def test_create_http_security_profile(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_http_profile',
            description='this is a test profile',
            evasion_techniques=dict(alarm=False, block=True),
            file_type=dict(
                alarm=False,
                block=False,
                allowed=['ZIP', 'JS', 'JSON']
            ),
            http_protocol_checks=dict(
                bad_host_header='yes',
                bad_version='on',
                body_in_get_head=True,
                high_ascii_in_headers='true'
            ),
            method=dict(
                block=True,
                allowed_methods=['GET', 'POST', 'PATCH']
            ),
            header=dict(
                alarm=False,
                mandatory_headers=['authorization', 'cookie']
            ),
            length=dict(
                post_data=0,
                request=2048,
                uri=512
            ),
            response=dict(
                type='redirect',
                url='https://you-are-banned.net',
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertDictEqual(results['evasion_techniques'], {'alarm': 'no', 'block': 'yes'})
        self.assertDictEqual(results['response'], {'type': 'redirect', 'url': 'https://you-are-banned.net'})
        self.assertDictEqual(results['file_type'], {'alarm': 'no', 'block': 'no', 'allowed': ['ZIP', 'JS', 'JSON']})
        self.assertDictEqual(
            results['http_protocol_checks'],
            {'bad_host_header': 'yes', 'bad_version': 'yes', 'body_in_get_head': 'yes', 'high_ascii_in_headers': 'yes'}
        )
        self.assertDictEqual(results['method'], {'block': 'yes', 'allowed_methods': ['GET', 'POST', 'PATCH']})
        self.assertDictEqual(results['header'], {'alarm': 'no', 'mandatory_headers': ['authorization', 'cookie']})
        self.assertDictEqual(results['length'], {'request': 2048, 'uri': 512, 'post_data': 0})

    def test_create_http_security_profile_no_change(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_http_profile',
            description='this is a test profile',
            evasion_techniques=dict(alarm=False, block=True),
            file_type=dict(
                alarm=False,
                block=False,
                allowed=['ZIP', 'JS', 'JSON']
            ),
            http_protocol_checks=dict(
                bad_host_header='yes',
                bad_version='on',
                body_in_get_head=True,
                high_ascii_in_headers='true'
            ),
            method=dict(
                block=True,
                allowed_methods=['GET', 'POST', 'PATCH']
            ),
            header=dict(
                alarm=False,
                mandatory_headers=['authorization', 'cookie']
            ),
            length=dict(
                post_data=0,
                request=2048,
                uri=512
            ),
            response=dict(
                type='redirect',
                url='https://you-are-banned.net',
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_http_security_profile.json')))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_create_http_security_profile_fails(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(name='test_http_profile'))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=401, contents={'access denied'}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(mm.client.post.called)

    def test_update_http_security_profile(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_http_profile',
            file_type=dict(
                disallowed=['ZIP', 'JS', 'JSON']
            ),
            http_protocol_checks=dict(
                bad_host_header='no',
                bad_version='off',
            ),
            method=dict(
                allowed_methods=['GET', 'PATCH']
            ),
            response=dict(
                type='default'
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_http_security_profile.json')))
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(results['file_type'], {'disallowed': ['ZIP', 'JS', 'JSON']})
        self.assertDictEqual(results['http_protocol_checks'], {'bad_host_header': 'no', 'bad_version': 'no'})
        self.assertDictEqual(results['response'], {'type': 'default'})
        self.assertDictEqual(results['method'], {'allowed_methods': ['GET', 'PATCH']})

    def test_update_http_security_profile_no_change(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_http_profile',
            file_type=dict(
                disallowed=['ZIP', 'JS', 'JSON']
            ),
            http_protocol_checks=dict(
                bad_host_header='no',
                bad_version='off',
            ),
            method=dict(
                allowed_methods=['GET', 'PATCH']
            ),
            response=dict(
                type='default'
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('load_http_security_profile_changed.json')
        ))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_update_http_security_profile_fails(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_http_profile',
            file_type=dict(
                disallowed=['ZIP', 'JS', 'JSON']
            ),
            http_protocol_checks=dict(
                bad_host_header='no',
                bad_version='off',
            ),
            method=dict(
                allowed_methods=['GET', 'PATCH']
            ),
            response=dict(
                type='default'
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_http_security_profile.json')))
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))
        mm.client.patch = Mock(return_value=dict(code=401, contents={'access denied'}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(mm.client.patch.called)

    def test_delete_http_security_profile(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_http_profile',
            state='absent'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_delete_http_security_profile_fails(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_http_profile',
            state='absent'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, True])
        mm.client.delete = Mock(return_value=dict(code=200, contents={}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the resource.', err.exception.args[0])
        self.assertTrue(mm.client.delete.called)

    def test_delete_http_security_profile_error_response(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_http_profile',
            state='absent'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.delete = Mock(return_value=dict(code=401, contents={'access denied'}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(mm.client.delete.called)

    @patch.object(bigip_security_http_profile, 'Connection')
    @patch.object(bigip_security_http_profile.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_security_http_profile.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_security_http_profile, 'Connection')
    @patch.object(bigip_security_http_profile.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_security_http_profile.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name="foobar",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[dict(code=200), dict(code=404), dict(code=400, contents='server error'),
                                          dict(code=401, contents='access denied')])

        res1 = mm.exists()
        self.assertTrue(res1)

        res2 = mm.exists()
        self.assertFalse(res2)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

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

        mm._update_changed_options = Mock(return_value=False)
        mm.read_current_from_device = Mock(return_value=dict())
        self.assertFalse(mm.update())
