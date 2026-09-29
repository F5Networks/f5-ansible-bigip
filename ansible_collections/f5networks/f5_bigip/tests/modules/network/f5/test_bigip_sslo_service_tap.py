# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_tap import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
)
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
            name='tap_test',
            devices=dict(
                interface='1.1',
                tag=400
            ),
            mac_address='fa:15:4e:a2:43:a8',
            port_remap=80
        )
        p = ModuleParameters(params=args)
        assert p.devices == {
            'name': 'ssloN_tap_test', 'interface': '1.1', 'path': '/Common/ssloN_tap_test.app/ssloN_tap_test',
            'tag': 400, 'ipv4_deviceip': '198.19.182.10', 'ipv4_haselfip': '198.19.182.9',
            'ipv4_selfip': '198.19.182.8', 'ipv4_subnet': '198.19.182.0', 'ipv6_deviceip': '2001:200:0:ca9a::a',
            'ipv6_haselfip': '2001:200:0:ca9a::9', 'ipv6_selfip': '2001:200:0:ca9a::8', 'ipv6_subnet': '2001:200:0:ca9a::'
        }
        assert p.mac_address == 'fa:15:4e:a2:43:a8'
        assert p.port_remap == 80
        assert p.service_down_action is None

    def test_api_parameters(self):
        args = load_fixture('return_sslo_tap_params.json')
        p = ApiParameters(params=args)

        assert p.devices == {
            'name': 'ssloN_tap_test', 'interface': '1.1', 'path': '/Common/ssloN_tap_test.app/ssloN_tap_test',
            'tag': 400, 'ipv4_deviceip': '198.19.182.10', 'ipv4_haselfip': '198.19.182.9',
            'ipv4_selfip': '198.19.182.8', 'ipv4_subnet': '198.19.182.0', 'ipv6_deviceip': '2001:200:0:ca9a::a',
            'ipv6_haselfip': '2001:200:0:ca9a::9', 'ipv6_selfip': '2001:200:0:ca9a::8',
            'ipv6_subnet': '2001:200:0:ca9a::'
        }
        assert p.mac_address == 'fa:16:3e:a1:42:a8'
        assert p.port_remap == 80
        assert p.service_down_action == 'ignore'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_tap.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_tap.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '7.5'
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_tap.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

    def test_create_tap_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_tap_create_generated.json')

        set_module_args(dict(
            name='tap_test',
            devices=dict(
                interface='1.1',
                tag=400
            ),
            mac_address='fa:16:3e:a1:42:a8',
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

    def test_modify_tap_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_tap_modify_generated.json')
        set_module_args(dict(
            name='tap_test',
            port_remap=8081,
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_tap.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_delete_tap_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_tap_delete_generated.json')
        set_module_args(dict(
            name='tap_test',
            state='absent',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_tap_modified.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(return_value=exists)

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_tap_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='tap_test',
            devices=dict(
                interface='1.1',
                tag=400
            ),
            mac_address='fa:16:3e:a1:42:a8',
            port_remap=8080
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_tap_create_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_tap_create_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['port_remap'] == 8080
        assert results['mac_address'] == 'fa:16:3e:a1:42:a8'
        assert results['devices'] == {
            'name': 'ssloN_tap_test', 'interface': '1.1', 'path': '/Common/ssloN_tap_test.app/ssloN_tap_test',
            'tag': 400, 'ipv4_deviceip': '198.19.182.10', 'ipv4_haselfip': '198.19.182.9',
            'ipv4_selfip': '198.19.182.8', 'ipv4_subnet': '198.19.182.0', 'ipv6_deviceip': '2001:200:0:ca9a::a',
            'ipv6_haselfip': '2001:200:0:ca9a::9', 'ipv6_selfip': '2001:200:0:ca9a::8',
            'ipv6_subnet': '2001:200:0:ca9a::'
        }

    def test_modify_tap_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='tap_test',
            mac_address='fa:16:3e:a1:42:a9',
            port_remap=8081
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_tap.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_tap_modify_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_tap_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['port_remap'] == 8081
        assert results['mac_address'] == 'fa:16:3e:a1:42:a9'

    def test_delete_tap_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_tap_delete_generated.json')
        set_module_args(dict(
            name='tap_test',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_tap_modified.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_tap_delete_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_tap_delete_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, done])

        results = mm.exec_module()
        assert results['changed'] is True

    def test_timeout_below_min_raises(self):
        p = ModuleParameters(params=dict(name='tap1', timeout=5))
        with self.assertRaisesRegex(Exception, 'Timeout value must be between 10 and 1800'):
            p.timeout

    def test_timeout_above_max_raises(self):
        p = ModuleParameters(params=dict(name='tap1', timeout=2000))
        with self.assertRaisesRegex(Exception, 'Timeout value must be between 10 and 1800'):
            p.timeout

    def test_unsupported_sslo_version_raises(self):
        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

        set_module_args(dict(name='tap1', devices=dict(interface='1.1')))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)

        with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_tap.sslo_version', return_value='6.0'):
            with self.assertRaisesRegex(F5ModuleError, 'Unsupported SSL Orchestrator version'):
                mm.check_sslo_version()

    def test_devices_required_on_create_raises(self):
        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

        set_module_args(dict(name='tap1'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaisesRegex(F5ModuleError, 'Devices must be defined'):
            mm.check_for_required_create_parameters()

    def test_exists_api_error_raises(self):
        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

        set_module_args(dict(name='tap1', devices=dict(interface='1.1')))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='exists error'))

        with self.assertRaisesRegex(F5ModuleError, 'exists error'):
            mm.exists()

    def test_create_api_error_raises(self):
        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

        set_module_args(dict(name='tap1', devices=dict(interface='1.1')))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.version = '7.5'
        mm.changes = Mock(to_return=Mock(return_value={}))
        mm.client.post = Mock(return_value=dict(code=500, contents='create error'))

        with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_tap.process_json', return_value={}):
            with self.assertRaisesRegex(F5ModuleError, 'create error'):
                mm.create_on_device()

    def test_update_api_error_raises(self):
        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

        set_module_args(dict(name='tap1', port_remap=8081))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.version = '7.5'
        mm.have = Mock(port_remap=8080)
        mm.changes = Mock(to_return=Mock(return_value={}))
        mm.client.post = Mock(return_value=dict(code=500, contents='update error'))

        with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_tap.process_json', return_value={}):
            with self.assertRaisesRegex(F5ModuleError, 'update error'):
                mm.update_on_device()

    def test_read_api_error_raises(self):
        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

        set_module_args(dict(name='tap1'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='read error'))

        with self.assertRaisesRegex(F5ModuleError, 'read error'):
            mm.read_current_from_device()

    def test_delete_api_error_raises(self):
        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

        set_module_args(dict(name='tap1', state='absent'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.version = '7.5'
        mm.client.post = Mock(return_value=dict(code=500, contents='delete error'))

        with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_tap.process_json', return_value={}):
            with self.assertRaisesRegex(F5ModuleError, 'delete error'):
                mm.remove_from_device()

    def test_check_task_api_error_raises(self):
        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

        set_module_args(dict(name='tap1'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='task check error'))

        with self.assertRaisesRegex(F5ModuleError, 'task check error'):
            mm._check_task_on_device('task-id')

    def test_task_failure_raises(self):
        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

        set_module_args(dict(name='tap1', devices=dict(interface='1.1')))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.want = Mock(timeout=(1, 10))
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents={'items': [{'id': 'task-id', 'state': 'ERROR', 'error': 'task failed'}]}
        ))

        with self.assertRaisesRegex(F5ModuleError, 'operation error'):
            mm.wait_for_task('task-id')

    def test_task_timeout_raises(self):
        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

        set_module_args(dict(name='tap1', timeout=10))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.want = Mock(timeout=(1, 10))
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents={'items': [{'id': 'task-id', 'state': 'PENDING'}]}
        ))

        with self.assertRaisesRegex(F5ModuleError, 'Module timeout reached'):
            mm.wait_for_task('task-id')

    def test_idempotent_absent_no_change(self):
        set_module_args(dict(name='nonexistent', state='absent'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)

        mm.client.get = Mock(return_value=dict(code=200, contents={'items': []}))

        results = mm.exec_module()

        assert results['changed'] is False


class TestMainFunction(unittest.TestCase):
    """Test main() entry point"""

    def test_main_function_success(self):
        from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_sslo_service_tap

        module = Mock(_socket_path='/tmp/socket')
        manager = Mock()
        manager.exec_module.return_value = {'changed': False}

        with patch.object(bigip_sslo_service_tap, 'AnsibleModule', return_value=module), \
                patch.object(bigip_sslo_service_tap, 'Connection'), \
                patch.object(bigip_sslo_service_tap, 'ModuleManager', return_value=manager):
            bigip_sslo_service_tap.main()

        module.exit_json.assert_called_once_with(changed=False)

    def test_main_function_failed(self):
        from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_sslo_service_tap
        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

        module = Mock(_socket_path='/tmp/socket')
        manager = Mock()
        manager.exec_module.side_effect = F5ModuleError('service failed')

        with patch.object(bigip_sslo_service_tap, 'AnsibleModule', return_value=module), \
                patch.object(bigip_sslo_service_tap, 'Connection'), \
                patch.object(bigip_sslo_service_tap, 'ModuleManager', return_value=manager):
            bigip_sslo_service_tap.main()

        module.fail_json.assert_called_once_with(msg='service failed')

    def test_update_tap_idempotent(self, *args):
        manager = ModuleManager.__new__(ModuleManager)
        manager.read_current_from_device = Mock()
        manager.should_update = Mock(return_value=False)
        manager.module = Mock(check_mode=False)

        assert manager.update() is False
        manager.read_current_from_device.assert_called_once()
        manager.should_update.assert_called_once()
