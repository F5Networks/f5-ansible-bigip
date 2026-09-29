# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_offbox_awaf import (
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
            name='awaf1a',
            devices_to=dict(
                vlan='/Common/sslo-inbound-vlan',
                self_ip='198.19.128.10',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                interface='1.1',
                tag=50,
                self_ip='198.19.128.138',
                netmask='255.255.255.128'
            ),
            rules=['/Common/rule1', '/Common/rule2'],
            devices=[dict(ip='198.19.128.30', port=80)],
            snat='snatpool',
            snat_pool='/Common/awaf1a-snatpool',
            snat_list=['198.19.64.10', '198.19.64.11'],
            http_profile='/Common/http',
            ip_family='ipv4',
            service_down_action='reset',
            port_remap=8080
        )

        p = ModuleParameters(params=args)
        assert p.devices == [{'ip': '198.19.128.30', 'port': 80}]
        assert p.devices_to == {
            'name': 'ssloN_awaf1a_in',
            'path': '/Common/sslo-inbound-vlan',
            'vlan': '/Common/sslo-inbound-vlan',
            'self_ip': '198.19.128.10',
            'netmask': '255.255.255.128',
            'network': '198.19.128.0'
        }
        assert p.devices_from == {
            'name': 'ssloN_awaf1a_out',
            'path': '/Common/ssloN_awaf1a_out.app/ssloN_awaf1a_out',
            'interface': '1.1', 'tag': 50,
            'self_ip': '198.19.128.138', 'netmask': '255.255.255.128',
            'network': '198.19.128.128'
        }
        assert p.name == 'ssloS_awaf1a'
        assert p.port_remap == 8080
        assert p.http_profile == '/Common/http'
        assert p.vendor_info == 'F5 Advanced WAF (Off-Box)'
        assert p.snat == 'existingSNAT'
        assert p.snat_list == [{'ip': '198.19.64.10'}, {'ip': '198.19.64.11'}]
        assert p.rules == [
            {'name': '/Common/rule1', 'value': '/Common/rule1'},
            {'name': '/Common/rule2', 'value': '/Common/rule2'}
        ]

    def test_vendor_info_default(self):
        p = ModuleParameters(params=dict(name='awaf1a'))
        assert p.vendor_info == 'F5 Advanced WAF (Off-Box)'

    def test_vendor_info_override(self):
        p = ModuleParameters(params=dict(name='awaf1a', vendor_info='Custom AWAF'))
        assert p.vendor_info == 'Custom AWAF'

    def test_devices_default_port(self):
        p = ModuleParameters(params=dict(name='awaf1a', devices=[dict(ip='198.19.128.30')]))
        assert p.devices == [{'ip': '198.19.128.30', 'port': 80}]

    def test_api_parameters(self):
        args = load_fixture('return_sslo_offbox_awaf_params.json')
        p = ApiParameters(params=args)

        assert p.devices == [{'ip': '198.19.128.30', 'port': 80}]
        assert p.devices_to == {
            'name': 'toNetwork',
            'path': '/Common/sslo-inbound-vlan',
            'self_ip': '198.19.128.10',
            'netmask': '255.255.255.128',
            'network': '198.19.128.0',
            'vlan': '/Common/sslo-inbound-vlan'
        }
        assert p.devices_from == {
            'name': 'fromNetwork',
            'path': '/Common/sslo-outbound-vlan',
            'self_ip': '198.19.128.138',
            'netmask': '255.255.255.128',
            'network': '198.19.128.128',
            'vlan': '/Common/sslo-outbound-vlan'
        }
        assert p.monitor == '/Common/gateway_icmp'
        assert p.ip_family == 'ipv4'
        assert p.port_remap == 8080
        assert p.http_profile == '/Common/http'
        assert p.service_down_action == 'reset'
        assert p.snat == 'existingSNAT'
        assert p.snat_pool == '/Common/awaf1a-snatpool'
        assert p.vendor_info == 'F5 Advanced WAF (Off-Box)'
        assert p.service_entry_sslprofile == '/Common/serverssl'
        assert p.service_return_sslprofile == '/Common/clientssl'
        assert p.rules == ['/Common/rule1']
        assert p.rules_egress == ['/Common/egress_rule1']
        assert p.default_persistence_profile == '/Common/cookie'

    def test_rules_egress_module_parameters(self):
        args = dict(
            name='awaf1a',
            devices_to=dict(vlan='/Common/vlan-in', self_ip='198.19.128.10', netmask='255.255.255.128'),
            devices_from=dict(vlan='/Common/vlan-out', self_ip='198.19.128.138', netmask='255.255.255.128'),
            devices=[dict(ip='198.19.128.30')],
            rules=['/Common/ingress1', '/Common/ingress2'],
            rules_egress=['/Common/egress1', '/Common/egress2'],
            default_persistence_profile='/Common/cookie',
        )
        p = ModuleParameters(params=args)
        assert p.rules == [
            {'name': '/Common/ingress1', 'value': '/Common/ingress1'},
            {'name': '/Common/ingress2', 'value': '/Common/ingress2'},
        ]
        assert p.rules_egress == [
            {'name': '/Common/egress1', 'value': '/Common/egress1'},
            {'name': '/Common/egress2', 'value': '/Common/egress2'},
        ]
        assert p.default_persistence_profile == '/Common/cookie'

    def test_auto_manage_defaults(self):
        p = ModuleParameters(params=dict(name='awaf1a'))
        assert p.auto_manage is True
        assert p.use_exist_selfip is False

    def test_auto_manage_false(self):
        p = ModuleParameters(params=dict(name='awaf1a', auto_manage=False))
        assert p.auto_manage is False

    def test_snat_translations(self):
        for user_val, internal_val in [
            ('none', 'None'), ('automap', 'AutoMap'), ('snatlist', 'SNAT'), ('snatpool', 'existingSNAT')
        ]:
            p = ModuleParameters(params=dict(name='awaf1a', snat=user_val))
            assert p.snat == internal_val

    def test_ip_family_default(self):
        p = ModuleParameters(params=dict(
            name='awaf1a',
            devices_to=dict(vlan='/Common/vlan-in', self_ip='198.19.128.10', netmask='255.255.255.128'),
            devices_from=dict(vlan='/Common/vlan-out', self_ip='198.19.128.138', netmask='255.255.255.128'),
            devices=[dict(ip='198.19.128.30')],
        ))
        assert p.ip_family is None

    def test_devices_to_interface_path(self):
        p = ModuleParameters(params=dict(
            name='awaf1a',
            devices_to=dict(interface='1.1', tag=100, self_ip='198.19.128.7', netmask='255.255.255.128'),
            devices_from=dict(vlan='/Common/vlan-out', self_ip='198.19.128.138', netmask='255.255.255.128'),
            devices=[dict(ip='198.19.128.30')],
        ))
        assert p.devices_to['path'] == '/Common/ssloN_awaf1a_in.app/ssloN_awaf1a_in'
        assert p.devices_to['interface'] == '1.1'
        assert p.devices_to['tag'] == 100


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch(
            'ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_offbox_awaf.F5Client'
        )
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch(
            'ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_offbox_awaf.sslo_version'
        )
        self.m3 = self.p3.start()
        self.m3.return_value = '9.0'

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_create_offbox_awaf_service_dump_json(self, *args):
        expected = load_fixture('sslo_offbox_awaf_create_generated.json')
        set_module_args(dict(
            name='awaf1a',
            devices_to=dict(
                vlan='/Common/awaf1a-in-vlan',
                self_ip='198.19.128.10',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                interface='1.1',
                tag=50,
                self_ip='198.19.128.138',
                netmask='255.255.255.128'
            ),
            devices=[dict(ip='198.19.128.30', port=80)],
            snat='snatpool',
            snat_pool='/Common/awaf1a-snatpool',
            ip_family='ipv4',
            service_down_action='reset',
            port_remap=8080,
            service_entry_sslprofile='/Common/serverssl',
            service_return_sslprofile='/Common/clientssl',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()
        assert results['changed'] is False
        assert results['json'] == expected

    def test_modify_offbox_awaf_service_dump_json(self, *args):
        expected = load_fixture('sslo_offbox_awaf_modify_generated.json')
        set_module_args(dict(
            name='awaf1a',
            devices=[dict(ip='10.10.100.100', port=3128), dict(ip='10.10.100.100', port=8080)],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_offbox_awaf.json'))
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()
        assert results['changed'] is False
        assert results['json'] == expected

    def test_delete_offbox_awaf_service_dump_json(self, *args):
        expected = load_fixture('sslo_offbox_awaf_delete_generated.json')
        set_module_args(dict(
            name='awaf1a',
            state='absent',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_offbox_awaf.json'))
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()
        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_offbox_awaf_service(self, *args):
        set_module_args(dict(
            name='awaf1a',
            devices_to=dict(
                vlan='/Common/awaf1a-in-vlan',
                self_ip='198.19.128.10',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                interface='1.1',
                tag=50,
                self_ip='198.19.128.138',
                netmask='255.255.255.128'
            ),
            devices=[dict(ip='198.19.128.30', port=80)],
            snat='snatpool',
            snat_pool='/Common/awaf1a-snatpool',
            ip_family='ipv4',
            service_down_action='reset',
            port_remap=8080
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_offbox_awaf_create_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_offbox_awaf_create_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['devices_to'] == {
            'vlan': '/Common/awaf1a-in-vlan',
            'self_ip': '198.19.128.10', 'netmask': '255.255.255.128'
        }
        assert results['devices_from'] == {
            'interface': '1.1', 'tag': 50,
            'self_ip': '198.19.128.138', 'netmask': '255.255.255.128'
        }
        assert results['devices'] == [{'ip': '198.19.128.30', 'port': 80}]
        assert results['ip_family'] == 'ipv4'
        assert results['service_down_action'] == 'reset'
        assert results['port_remap'] == 8080
        assert results['snat'] == 'snatpool'
        assert results['snat_pool'] == '/Common/awaf1a-snatpool'
        assert results['vendor_info'] == 'F5 Advanced WAF (Off-Box)'

    def test_modify_offbox_awaf_service(self, *args):
        set_module_args(dict(
            name='awaf1a',
            snat='snatlist',
            snat_list=['198.19.64.10', '198.19.64.11'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_offbox_awaf.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_offbox_awaf_modify_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_offbox_awaf_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['snat'] == 'snatlist'
        assert results['snat_list'] == ['198.19.64.10', '198.19.64.11']

    def test_delete_offbox_awaf_service(self, *args):
        set_module_args(dict(
            name='awaf1a',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_offbox_awaf.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_offbox_awaf_delete_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_offbox_awaf_delete_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True

    def test_create_offbox_awaf_with_rules_egress_and_persistence(self, *args):
        self.m3.return_value = '14.0'
        set_module_args(dict(
            name='awaf1a',
            devices_to=dict(
                vlan='/Common/awaf1a-in-vlan',
                self_ip='198.19.128.10',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                vlan='/Common/awaf1a-out-vlan',
                self_ip='198.19.128.138',
                netmask='255.255.255.128'
            ),
            devices=[dict(ip='198.19.128.30', port=80)],
            rules=['/Common/ingress1'],
            rules_egress=['/Common/egress1'],
            default_persistence_profile='/Common/cookie',
            ip_family='ipv4',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_offbox_awaf_create_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_offbox_awaf_create_done.json'))
        )

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['rules'] == ['/Common/ingress1']
        assert results['rules_egress'] == ['/Common/egress1']
        assert results['default_persistence_profile'] == '/Common/cookie'

    def test_modify_offbox_awaf_rules_egress_and_persistence(self, *args):
        self.m3.return_value = '14.0'
        set_module_args(dict(
            name='awaf1a',
            rules_egress=['/Common/egress1', '/Common/egress2'],
            default_persistence_profile='/Common/source_addr',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_offbox_awaf.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_offbox_awaf_modify_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_offbox_awaf_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['rules_egress'] == ['/Common/egress1', '/Common/egress2']
        assert results['default_persistence_profile'] == '/Common/source_addr'

    def test_create_offbox_awaf_auto_manage_true_new_vlan_dump_json(self, *args):
        set_module_args(dict(
            name='awaf1a',
            auto_manage=True,
            devices_to=dict(
                interface='1.1',
                tag=100,
                self_ip='198.19.128.7',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                interface='1.2',
                tag=101,
                self_ip='198.19.128.245',
                netmask='255.255.255.128'
            ),
            devices=[dict(ip='198.19.128.30', port=80)],
            ip_family='ipv4',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()
        assert results['changed'] is False
        assert 'json' in results
        payload = results['json']
        service = payload['inputProperties'][2]['value']['customService']
        assert service['isAutoManage'] is True
        assert service['managedNetwork']['isAutoManage'] is True
        network_block = payload['inputProperties'][1]['value']
        assert len(network_block) == 2
        for net in network_block:
            assert net['selfIpConfig']['selfIp'] == ''
            assert net['selfIpConfig']['create'] is False

    def test_create_offbox_awaf_auto_manage_true_existing_vlan_dump_json(self, *args):
        set_module_args(dict(
            name='awaf1a',
            auto_manage=True,
            devices_to=dict(
                vlan='/Common/L3-INGRESS',
                self_ip='198.19.128.7',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                vlan='/Common/L3-EGRESS',
                self_ip='198.19.128.245',
                netmask='255.255.255.128'
            ),
            devices=[dict(ip='198.19.128.30', port=80)],
            ip_family='ipv4',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()
        assert results['changed'] is False
        assert 'json' in results
        payload = results['json']
        service = payload['inputProperties'][2]['value']['customService']
        assert service['isAutoManage'] is True
        assert payload['inputProperties'][1]['value'] == []

    def test_create_offbox_awaf_use_exist_selfip_dump_json(self, *args):
        set_module_args(dict(
            name='awaf1a',
            auto_manage=False,
            use_exist_selfip=True,
            devices_to=dict(
                vlan='/Common/L3-INGRESS',
                self_ip='10.10.14.11',
                netmask='255.255.255.0'
            ),
            devices_from=dict(
                vlan='/Common/L3-EGRESS',
                self_ip='10.10.15.106',
                netmask='255.255.255.0'
            ),
            devices=[dict(ip='10.10.14.28', port=80)],
            ip_family='ipv4',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()
        assert results['changed'] is False
        assert 'json' in results
        payload = results['json']
        assert payload['inputProperties'][1]['value'] == []
        service = payload['inputProperties'][2]['value']['customService']
        assert service['isAutoManage'] is False
        conn = service['connectionInformation']
        assert conn['fromBigipNetwork']['name'] == 'toNetwork'
        assert conn['toBigipNetwork']['name'] == 'fromNetwork'

    def test_update_offbox_awaf_idempotent(self, *args):
        manager = ModuleManager.__new__(ModuleManager)
        manager.read_current_from_device = Mock()
        manager.should_update = Mock(return_value=False)
        manager.module = Mock(check_mode=False)

        assert manager.update() is False
        manager.read_current_from_device.assert_called_once()
        manager.should_update.assert_called_once()


if __name__ == '__main__':
    unittest.main()
