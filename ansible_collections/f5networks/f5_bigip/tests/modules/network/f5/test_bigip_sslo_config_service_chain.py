# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain import (
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
            name="demo_chain_1",
            services=[
                dict(service_name="icap1", type="icap", ip_family="ipv4"),
                dict(service_name="layer3a", type="L3")
            ]
        )
        p = ModuleParameters(params=args)
        assert p.name == 'ssloSC_demo_chain_1'
        assert p.services == [{'name': 'ssloS_icap1', 'ipFamily': 'ipv4', 'serviceType': 'icap'},
                              {'name': 'ssloS_layer3a', 'ipFamily': 'ipv4', 'serviceType': 'L3'}]

    def test_api_parameters(self):
        args = load_fixture('return_sslo_service_chain_params.json')

        p = ApiParameters(params=args)
        assert p.name == 'ssloSC_demo_chain_1'
        assert p.services == [{'name': 'ssloS_icap1', 'ipFamily': 'ipv4', 'serviceType': 'icap'},
                              {'name': 'ssloS_layer3a', 'ipFamily': 'ipv4', 'serviceType': 'L3'}]

    def test_module_parameters_awaf_onbox(self):
        args = dict(
            name="chain_waf",
            services=[
                dict(service_name="ssloS_F5_AWAF", type="awaf", ip_family="ipv4")
            ]
        )
        p = ModuleParameters(params=args)
        assert p.name == 'ssloSC_chain_waf'
        assert p.services == [{'name': 'ssloS_F5_AWAF', 'ipFamily': 'ipv4', 'serviceType': 'awaf'}]

    def test_module_parameters_awaf_offbox(self):
        args = dict(
            name="chain_waf",
            services=[
                dict(service_name="ssloS_F5_AWAF_OffBox", type="awaf-off-box", ip_family="ipv4")
            ]
        )
        p = ModuleParameters(params=args)
        assert p.name == 'ssloSC_chain_waf'
        assert p.services == [{'name': 'ssloS_F5_AWAF_OffBox', 'ipFamily': 'ipv4', 'serviceType': 'awaf-off-box'}]

    def test_module_parameters_mixed_chain(self):
        args = dict(
            name="chain_mixed",
            services=[
                dict(service_name="ssloS_F5_AWAF", type="awaf"),
                dict(service_name="ssloS_F5_AWAF_OffBox", type="awaf-off-box", ip_family="ipv6")
            ]
        )
        p = ModuleParameters(params=args)
        assert p.services == [
            {'name': 'ssloS_F5_AWAF', 'ipFamily': 'ipv4', 'serviceType': 'awaf'},
            {'name': 'ssloS_F5_AWAF_OffBox', 'ipFamily': 'ipv6', 'serviceType': 'awaf-off-box'}
        ]

    def test_module_parameters_o365(self):
        args = dict(
            name="chain_o365",
            services=[
                dict(service_name="ssloS_o365", type="f5-tenant-restrictions", ip_family="ipv4")
            ]
        )
        p = ModuleParameters(params=args)
        assert p.name == 'ssloSC_chain_o365'
        assert p.services == [{'name': 'ssloS_o365', 'ipFamily': 'ipv4', 'serviceType': 'f5-tenant-restrictions'}]


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '9.0'
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

    def test_create_service_chain_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_sc_create_generated.json')
        set_module_args(dict(
            name="foobar",
            services=[
                dict(service_name="icap1", type="icap", ip_family="ipv4")
            ],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_modify_service_chain_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_sc_modify_generated.json')
        set_module_args(dict(
            name="foobar",
            services=[
                dict(service_name="layer3a", type="L3", ip_family="ipv4")
            ],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_sc.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_delete_service_chain_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_sc_delete_generated.json')
        set_module_args(dict(
            name='foobar',
            dump_json=True,
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_sslo_sc.json')))

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_service_chain_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name="foobar",
            services=[
                dict(service_name="icap1", type="icap", ip_family="ipv4")
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_sc_create_start.json')))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('reply_sslo_sc_create_done.json')))

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['services'] == [{'name': 'ssloS_icap1', 'ipFamily': 'ipv4', 'serviceType': 'icap'}]

    def test_modify_service_chain_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name="foobar",
            services=[
                dict(service_name="layer3a", type="L3", ip_family="ipv4")
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_sc.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_sc_modify_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_sc_modify_start.json')))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['services'] == [{'name': 'ssloS_layer3a', 'ipFamily': 'ipv4', 'serviceType': 'L3'}]

    def test_delete_service_chain_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='foobar',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_sc.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_sc_delete_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_sc_delete_start.json')))
        mm.client.get = Mock(side_effect=[exists, done])

        results = mm.exec_module()
        assert results['changed'] is True

    def test_create_api_error_on_post(self, *args):
        set_module_args(dict(
            name='foobar',
            services=[dict(service_name='icap1', type='icap')]
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=400, contents='Bad request'))

        with self.assertRaises(Exception) as ctx:
            mm.exec_module()
        assert 'Bad request' in str(ctx.exception)

    def test_remove_api_error_on_post(self, *args):
        set_module_args(dict(
            name='foobar',
            state='absent'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        exists_resp = dict(code=200, contents=load_fixture('load_sslo_sc.json'))
        mm.client.get = Mock(return_value=exists_resp)
        mm.client.post = Mock(return_value=dict(code=403, contents='Forbidden'))

        with self.assertRaises(Exception) as ctx:
            mm.exec_module()
        assert 'Forbidden' in str(ctx.exception)

    def test_read_current_from_device_error(self, *args):
        set_module_args(dict(
            name='foobar',
            services=[dict(service_name='icap1', type='icap')]
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        exists_resp = dict(code=200, contents=load_fixture('load_sslo_sc.json'))
        read_error = dict(code=503, contents='Service unavailable')
        mm.client.get = Mock(side_effect=[exists_resp, read_error])
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_sc_modify_start.json')))

        with self.assertRaises(Exception) as ctx:
            mm.exec_module()
        assert 'Service unavailable' in str(ctx.exception)

    def test_exists_check_error(self, *args):
        set_module_args(dict(
            name='foobar',
            services=[dict(service_name='icap1', type='icap')]
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='Server error'))

        with self.assertRaises(Exception) as ctx:
            mm.exec_module()
        assert 'Server error' in str(ctx.exception)

    def test_idempotent_create_when_exists(self, *args):
        set_module_args(dict(
            name='foobar',
            services=[dict(service_name='icap1', type='icap', ip_family='ipv4')]
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        exists_resp = dict(code=200, contents=load_fixture('load_sslo_sc.json'))
        mm.client.get = Mock(side_effect=[exists_resp, exists_resp])

        result = mm.exec_module()
        assert result['changed'] is False

    def test_idempotent_update_when_no_changes(self, *args):
        set_module_args(dict(
            name='foobar',
            services=[dict(service_name='icap1', type='icap', ip_family='ipv4')]
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        exists_resp = dict(code=200, contents=load_fixture('load_sslo_sc.json'))
        mm.client.get = Mock(side_effect=[exists_resp, exists_resp, exists_resp])

        result = mm.exec_module()
        assert result['changed'] is False

    def test_main_function_success(self, *args):
        from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain import main

        with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain.AnsibleModule') as mock_module:
            with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain.Connection'):
                mock_instance = MagicMock()
                mock_module.return_value = mock_instance
                mock_instance.params = dict(name='test', services=[])

                with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain.ModuleManager') as mock_mm:
                    mm_instance = MagicMock()
                    mock_mm.return_value = mm_instance
                    mm_instance.exec_module.return_value = dict(changed=True)

                    main()
                    mock_instance.exit_json.assert_called_once()

    def test_main_function_failed(self, *args):
        from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain import main
        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

        with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain.AnsibleModule') as mock_module:
            with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain.Connection'):
                mock_instance = MagicMock()
                mock_module.return_value = mock_instance
                mock_instance.params = dict(name='test')

                with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain.ModuleManager') as mock_mm:
                    mm_instance = MagicMock()
                    mock_mm.return_value = mm_instance
                    mm_instance.exec_module.side_effect = F5ModuleError('Test error')

                    main()
                    mock_instance.fail_json.assert_called_once()

    def test_service_chain_with_multiple_services(self, *args):
        set_module_args(dict(
            name='foobar',
            services=[
                dict(service_name='icap1', type='icap', ip_family='ipv4'),
                dict(service_name='layer3a', type='L3', ip_family='ipv4'),
                dict(service_name='awaf1', type='awaf', ip_family='ipv6')
            ]
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_sc_create_start.json')))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('reply_sslo_sc_create_done.json')))

        results = mm.exec_module()
        assert results['changed'] is True
        assert len(results['services']) == 3

    def test_update_service_chain_idempotent(self, *args):
        manager = ModuleManager.__new__(ModuleManager)
        manager.read_current_from_device = Mock()
        manager.should_update = Mock(return_value=False)
        manager.module = Mock(check_mode=False)

        assert manager.update() is False
        manager.read_current_from_device.assert_called_once()
        manager.should_update.assert_called_once()

    def test_module_parameters_awaf_onbox(self):
        args = dict(
            name="chain_waf",
            services=[
                dict(service_name="ssloS_F5_AWAF", type="awaf", ip_family="ipv4")
            ]
        )
        p = ModuleParameters(params=args)
        assert p.name == 'ssloSC_chain_waf'
        assert p.services == [{'name': 'ssloS_F5_AWAF', 'ipFamily': 'ipv4', 'serviceType': 'awaf'}]

    def test_module_parameters_awaf_offbox(self):
        args = dict(
            name="chain_waf",
            services=[
                dict(service_name="ssloS_F5_AWAF_OffBox", type="awaf-off-box", ip_family="ipv4")
            ]
        )
        p = ModuleParameters(params=args)
        assert p.name == 'ssloSC_chain_waf'
        assert p.services == [{'name': 'ssloS_F5_AWAF_OffBox', 'ipFamily': 'ipv4', 'serviceType': 'awaf-off-box'}]

    def test_module_parameters_mixed_chain(self):
        args = dict(
            name="chain_mixed",
            services=[
                dict(service_name="ssloS_F5_AWAF", type="awaf"),
                dict(service_name="ssloS_F5_AWAF_OffBox", type="awaf-off-box", ip_family="ipv6")
            ]
        )
        p = ModuleParameters(params=args)
        assert p.services == [
            {'name': 'ssloS_F5_AWAF', 'ipFamily': 'ipv4', 'serviceType': 'awaf'},
            {'name': 'ssloS_F5_AWAF_OffBox', 'ipFamily': 'ipv6', 'serviceType': 'awaf-off-box'}
        ]
