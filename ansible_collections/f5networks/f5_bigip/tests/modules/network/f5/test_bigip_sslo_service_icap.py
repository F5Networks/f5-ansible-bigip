# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_icap import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_sslo_service_icap
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
            name='foobar',
            ip_family='ipv4',
            devices=[
                dict(
                    ip='1.1.1.1',
                    port=1344
                ),
                dict(
                    ip='2.2.2.2',
                    port=1348
                )
            ],
            headers=dict(
                enable='yes',
                referrer='foo_referrer',
                host='foo_host',
                user_agent='foo_ua',
                h_from='foo_from'
            ),
            enable_one_connect='yes',
            request_uri='/avscan',
            response_uri='/avscan',
            preview_length=2048,
            service_down_action='ignore',
            allow_http10='no'
        )

        p = ModuleParameters(params=args)
        assert p.name == 'ssloS_foobar'
        assert p.allow_http10 is False
        assert p.enable_one_connect is True
        assert p.header_enable is True
        assert p.header_from == 'foo_from'
        assert p.header_host == 'foo_host'
        assert p.header_referrer == 'foo_referrer'
        assert p.header_user_agent == 'foo_ua'
        assert p.preview_length == 2048
        assert p.request_uri == 'icap://${SERVER_IP}:${SERVER_PORT}/avscan'
        assert p.response_uri == 'icap://${SERVER_IP}:${SERVER_PORT}/avscan'
        assert p.service_down_action == 'ignore'
        assert p.devices == [{'port': 1344, 'ip': '1.1.1.1'}, {'port': 1348, 'ip': '2.2.2.2'}]

    def test_api_parameters(self):
        args = load_fixture('return_sslo_icap_params.json')
        p = ApiParameters(params=args)

        assert p.devices == [{'port': 1344, 'ip': '1.1.1.1'}, {'port': 1348, 'ip': '2.2.2.2'}]
        assert p.allow_http10 is False
        assert p.enable_one_connect is True
        assert p.header_enable is True
        assert p.header_from == 'foo_from'
        assert p.header_host == 'foo_host'
        assert p.header_referrer == 'foo_referrer'
        assert p.header_user_agent == 'foo_ua'
        assert p.ip_family == 'ipv4'
        assert p.monitor == '/Common/tcp'
        assert p.preview_length == 2048
        assert p.response_uri == 'icap://${SERVER_IP}:${SERVER_PORT}/avscan'
        assert p.request_uri == 'icap://${SERVER_IP}:${SERVER_PORT}/avscan'
        assert p.service_down_action == 'ignore'

    def test_invalid_preview_value(self):
        args = dict(
            preview_length=9999999
        )

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.preview_length is None
        assert str(res.exception) == 'Invalid preview_length value got: 9999999 bytes, ' \
                                     'valid value range is between 0 and 51200 bytes.'

    def test_invalid_device_port_raises(self):
        p = ModuleParameters(params=dict(name='icap', devices=[dict(ip='1.1.1.1', port=65536)]))

        with self.assertRaisesRegex(F5ModuleError, '0 - 65535'):
            p.devices

    def test_timeout_outside_supported_range_raises(self):
        for timeout in (9, 1801):
            p = ModuleParameters(params=dict(name='icap', timeout=timeout))
            with self.assertRaisesRegex(F5ModuleError, 'between 10 and 1800'):
                p.timeout

    def test_uri_values_are_rendered_for_icap_servers(self):
        p = ModuleParameters(params=dict(name='icap', request_uri='/', response_uri='/response'))

        assert p.request_uri == 'icap://${SERVER_IP}:${SERVER_PORT}/'
        assert p.response_uri == 'icap://${SERVER_IP}:${SERVER_PORT}/response'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_icap.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_icap.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '9.0'
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_icap.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

    def test_create_icap_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_icap_create_generated.json')
        set_module_args(dict(
            name='foobar',
            ip_family='ipv4',
            devices=[
                dict(
                    ip='1.1.1.1',
                    port=1344
                ),
                dict(
                    ip='2.2.2.2',
                    port=1348
                )
            ],
            headers=dict(
                enable='yes',
                referrer='foo_referrer',
                host='foo_host',
                user_agent='foo_ua',
                h_from='foo_from'
            ),
            enable_one_connect='yes',
            request_uri='/avscan',
            response_uri='/avscan',
            preview_length=2048,
            service_down_action='ignore',
            allow_http10='no',
            cpm_policies='/Common/test_icaps',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_modify_icap_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_icap_modify_generated.json')
        set_module_args(dict(
            name='foobar',
            headers=dict(
                enable='no'
            ),
            enable_one_connect='no',
            preview_length=1024,
            service_down_action='drop',
            allow_http10='yes',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_icap.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_delete_icap_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_icap_delete_generated.json')
        set_module_args(dict(
            name='foobar',
            state='absent',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_sslo_service_icap.json')))

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_icap_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='foobar',
            ip_family='ipv4',
            devices=[
                dict(
                    ip='1.1.1.1',
                    port=1344
                ),
                dict(
                    ip='2.2.2.2',
                    port=1348
                )
            ],
            headers=dict(
                enable='yes',
                referrer='foo_referrer',
                host='foo_host',
                user_agent='foo_ua',
                h_from='foo_from'
            ),
            enable_one_connect='yes',
            request_uri='/avscan',
            response_uri='/avscan',
            preview_length=2048,
            service_down_action='ignore',
            allow_http10='no',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_icap_create_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_icap_create_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['allow_http10'] is False
        assert results['devices'] == [{'port': 1344, 'ip': '1.1.1.1'}, {'port': 1348, 'ip': '2.2.2.2'}]
        assert results['enable_one_connect'] is True
        assert results['headers'] == {'enable': True, 'referrer': 'foo_referrer',
                                      'host': 'foo_host', 'user_agent': 'foo_ua', 'h_from': 'foo_from'}
        assert results['ip_family'] == 'ipv4'
        assert results['preview_length'] == 2048
        assert results['request_uri'] == 'icap://${SERVER_IP}:${SERVER_PORT}/avscan'
        assert results['response_uri'] == 'icap://${SERVER_IP}:${SERVER_PORT}/avscan'
        assert results['service_down_action'] == 'ignore'

    def test_modify_icap_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='foobar',
            headers=dict(
                enable='no'
            ),
            enable_one_connect='no',
            preview_length=1024,
            service_down_action='drop',
            allow_http10='yes',
            cpm_policies="/Common/test_icaps_updated"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_icap.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_icap_modify_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_icap_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['headers'] == {'enable': False}
        assert results['preview_length'] == 1024
        assert results['allow_http10'] is True
        assert results['enable_one_connect'] is False

    def test_delete_icap_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='foobar',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        exists = dict(code=200, contents=load_fixture('load_sslo_service_icap.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_icap_delete_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_icap_delete_start.json')))
        mm.client.get = Mock(side_effect=[exists, done])

        results = mm.exec_module()
        assert results['changed'] is True

    def test_create_icap_object_missing_devices(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        err = 'The devices parameter is not defined. Devices must be defined during CREATE operation.'
        set_module_args(dict(
            name='foobar'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,

        )
        mm = ModuleManager(module=module)
        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    def test_create_icap_object_missing_custom_headers(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        err = "The host parameter is not defined. Custom header configuration requires the 'referrer', 'host', " \
              "'user_agent' and 'h_from' values to be defined during CREATE operation when'enable' " \
              "parameter is set to 'True'."
        set_module_args(dict(
            name='fooicap',
            devices=[
                dict(
                    ip='1.1.1.1',
                    port=1344
                ),
                dict(
                    ip='2.2.2.2',
                    port=1348
                )
            ],
            headers=dict(
                enable='yes',
                referrer='foo_referrer'
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,

        )
        mm = ModuleManager(module=module)
        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    def test_create_requires_each_enabled_header_value(self):
        manager = ModuleManager.__new__(ModuleManager)
        for missing in ('header_referrer', 'header_host', 'header_user_agent', 'header_from'):
            manager.want = Mock(
                devices=[dict(ip='1.1.1.1', port=1344)], header_enable=True,
                header_referrer='referrer', header_host='host', header_user_agent='agent', header_from='from'
            )
            setattr(manager.want, missing, None)
            expected = missing.replace('header_', '')
            with self.assertRaisesRegex(F5ModuleError, expected):
                manager.check_for_required_create_parameters()

    def test_update_idempotent_and_absent_missing(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.read_current_from_device = Mock()
        manager.should_update = Mock(return_value=False)
        manager.module = Mock(check_mode=False)
        assert manager.update() is False
        manager.read_current_from_device.assert_called_once()

        manager.exists = Mock(return_value=False)
        assert manager.absent() is False

    def test_unsupported_sslo_version_raises(self):
        self.m3.return_value = '7.0'
        set_module_args(dict(name='icap'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        manager = ModuleManager(module=module)

        with self.assertRaisesRegex(F5ModuleError, 'Unsupported SSL Orchestrator version'):
            manager.check_sslo_version()

    def test_exists_error_raises(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(name='ssloS_icap')
        manager.client = Mock(get=Mock(return_value=dict(code=500, contents='exists failed')))

        with self.assertRaisesRegex(F5ModuleError, 'exists failed'):
            manager.exists()

    def test_create_update_and_remove_errors_raise(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(dump_json=False)
        manager.changes = Mock(to_return=Mock(return_value={}))
        manager.add_json_metadata = Mock(side_effect=lambda payload=None: payload or {})
        manager.add_create_values = Mock(side_effect=lambda payload: payload)
        manager.add_missing_options = Mock(side_effect=lambda payload: payload)
        manager.client = Mock(post=Mock(return_value=dict(code=500, contents='operation failed')))

        with patch.object(bigip_sslo_service_icap, 'process_json', return_value={}):
            for operation in (manager.create_on_device, manager.update_on_device, manager.remove_from_device):
                with self.assertRaisesRegex(F5ModuleError, 'operation failed'):
                    operation()

    def test_read_current_error_and_missing_item_raise(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(name='ssloS_icap')
        manager.client = Mock(get=Mock(return_value=dict(code=500, contents='read failed')))

        with self.assertRaisesRegex(F5ModuleError, 'read failed'):
            manager.read_current_from_device()

        manager.client.get.return_value = dict(code=200, contents={'items': []})
        with self.assertRaisesRegex(F5ModuleError, 'items'):
            manager.read_current_from_device()

    def test_wait_for_task_error_and_timeout_raise(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(timeout=(1, 1))
        manager.operation = 'CREATE'
        manager.delete_failed_operation_on_device = Mock()
        manager._check_task_on_device = Mock(return_value={'state': 'ERROR', 'error': 'task failed'})

        with self.assertRaisesRegex(F5ModuleError, 'task failed'):
            manager.wait_for_task('task-id')
        manager.delete_failed_operation_on_device.assert_called_once_with('task-id')

        manager._check_task_on_device = Mock(return_value={'state': 'RUNNING'})
        with self.assertRaisesRegex(F5ModuleError, 'Module timeout reached'):
            manager.wait_for_task('task-id')

    def test_check_task_on_device_error_raises(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.client = Mock(get=Mock(return_value=dict(code=500, contents='task lookup failed')))

        with self.assertRaisesRegex(F5ModuleError, 'task lookup failed'):
            manager._check_task_on_device('task-id')

    def test_main_function_success(self):
        module = Mock(_socket_path='/tmp/socket')
        manager = Mock()
        manager.exec_module.return_value = {'changed': False}
        with patch.object(bigip_sslo_service_icap, 'AnsibleModule', return_value=module), \
                patch.object(bigip_sslo_service_icap, 'Connection'), \
                patch.object(bigip_sslo_service_icap, 'HAS_PACKAGING', True), \
                patch.object(bigip_sslo_service_icap, 'ModuleManager', return_value=manager):
            bigip_sslo_service_icap.main()

        module.exit_json.assert_called_once_with(changed=False)

    def test_main_function_failed(self):
        module = Mock(_socket_path='/tmp/socket')
        manager = Mock()
        manager.exec_module.side_effect = F5ModuleError('service failed')
        with patch.object(bigip_sslo_service_icap, 'AnsibleModule', return_value=module), \
                patch.object(bigip_sslo_service_icap, 'Connection'), \
                patch.object(bigip_sslo_service_icap, 'HAS_PACKAGING', True), \
                patch.object(bigip_sslo_service_icap, 'ModuleManager', return_value=manager):
            bigip_sslo_service_icap.main()

        module.fail_json.assert_called_once_with(msg='service failed')
