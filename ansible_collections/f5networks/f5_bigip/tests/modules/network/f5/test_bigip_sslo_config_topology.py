# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_topology import (
    ModuleParameters, ArgumentSpec, ModuleManager
)
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
            topology_type='outbound_l3',
            protocol='tcp',
            ip_family='ipv4',
            source='1.2.3.4/32',
            dest='4.3.2.1/32',
            port=1234,
            tcp_settings_client='/Common/baz',
            tcp_settings_server='/Common/bar',
            vlans=['/Common/foo1', '/Common/foo2'],
            snat='snatpool',
            snat_list=['10.10.10.1', '10.10.10.2'],
            snat_pool='/Foo/snats',
            gateway='iplist',
            gateway_list=[dict(ip='2.2.2.2', ratio=2), dict(ip='3.3.3.3')],
            gateway_pool='/Foo/gws',
            l7_profile_type='http',
            l7_profile='/Bar/baz',
            additional_protocols=['ftp', 'imap', 'pop3', 'smtps'],
            access_profile='/Foo/access',
            profile_scope='named',
            profile_scope_value='scope_value',
            primary_auth_uri='/fake/uri',
            verify_accept='yes',
            oscp_auth='this_is_fake',
            proxy_ip='1.1.1.1',
            proxy_port=4321,
            auth_profile='/foo/fake',
            dns_resoler='baz_bar',
            pools='fake_pool',
            logging=dict(
                sslo='critical', per_request_policy='warning', ftp='information', pop3='notice', smtps='alert'
            ),
            ssl_settings='ssl_fake',
            security_policy='policy_fake'
        )

        p = ModuleParameters(params=args)
        assert p.name == 'sslo_foobar'
        assert p.topology == 'topology_l3_outbound'
        assert p.protocol == 'tcp'
        assert p.ip_family == 'ipv4'
        assert p.source == '1.2.3.4%0/32'
        assert p.dest == '4.3.2.1%0/32'
        assert p.port == 1234
        assert p.tcp_settings_client == '/Common/baz'
        assert p.tcp_settings_server == '/Common/bar'
        assert p.vlans == [
            {'name': '/Common/foo1', 'value': '/Common/foo1'}, {'name': '/Common/foo2', 'value': '/Common/foo2'}
        ]
        assert p.snat == 'existingSNAT'
        assert p.snat_list == [{'ip': '10.10.10.1'}, {'ip': '10.10.10.2'}]
        assert p.snat_pool == '/Foo/snats'
        assert p.gateway == 'newGatewayPool'
        assert p.gateway_list == [{'ip': '2.2.2.2', 'ratio': 2}, {'ip': '3.3.3.3', 'ratio': 1}]
        assert p.gateway_pool == '/Foo/gws'
        assert p.l7_profile_type == 'http'
        assert p.l7_profile == '/Bar/baz'
        assert p.additional_protocols == [
            {'name': 'FTP', 'value': 'ftp'}, {'name': 'IMAP', 'value': 'imap'},
            {'name': 'POP3', 'value': 'pop3'}, {'name': 'SMTPS', 'value': 'smtps'}
        ]
        assert p.access_profile == '/Foo/access'
        assert p.profile_scope == 'named'
        assert p.profile_scope_value == 'scope_value'
        assert p.primary_auth_uri == '/fake/uri'
        assert p.verify_accept is True
        assert p.oscp_auth == 'this_is_fake'
        assert p.proxy_ip == '1.1.1.1'
        assert p.proxy_port == 4321
        assert p.auth_profile == '/foo/fake'
        assert p.dns_resoler == 'baz_bar'
        assert p.pools == 'fake_pool'
        assert p.logging == {
            'sslo': 'crit', 'per_request_policy': 'warn', 'ftp': 'info', 'pop3': 'notice', 'smtps': 'alert'
        }
        assert p.ssl_settings == 'ssloT_ssl_fake'
        assert p.security_policy == 'ssloP_policy_fake'

    def test_returned_proxy_type_and_dep_net(self):
        args = dict(
            topology_type='outbound_l2'
        )
        p = ModuleParameters(params=args)

        assert p.topology == 'topology_l2_outbound'
        assert p.proxy_type == 'transparent'
        assert p.dep_net == 'l2_network'

    def test_returned_proxy_type_no_dep_net(self):
        args = dict(
            topology_type='outbound_explicit'
        )
        p = ModuleParameters(params=args)

        assert p.topology == 'topology_l3_explicit_proxy'
        assert p.proxy_type == 'explicit'
        assert p.dep_net is None

    def test_ignore_tcp_settings_client_server(self):
        args = dict(
            topology_type='outbound_explicit',
            tcp_settings_client='will_be_ignored_client',
            tcp_settings_server='will_be_ignored_server'
        )
        p = ModuleParameters(params=args)

        assert p.topology == 'topology_l3_explicit_proxy'
        assert p.proxy_type == 'explicit'
        assert p.tcp_settings_client is None
        assert p.tcp_settings_server is None

    def test_missing_mask_raises(self):
        args = dict(
            source='0.0.0.0%0'
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.source is None

        assert str(res.exception) == 'Address must contain a subnet (CIDR) value <= 32.'

    def test_invalid_mask_raises(self):
        args = dict(
            source='2001:0db8:85a3:0000:0000:8a2e:0370:7334/64'
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.source is None

        assert str(res.exception) == 'Address must contain a subnet (CIDR) value <= 32.'

    def test_invalid_port_raises(self):
        args = dict(
            port=-1
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.port is None

        assert str(res.exception) == 'Valid ports must be in range 0 - 65535.'

    def test_invalid_name_raises(self):
        args = dict(
            name='this_is_quite_long_and_will_raise_error'
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.name is None

        assert str(res.exception) == 'Maximum allowed name length is 15 characters.'

    def test_additional_protocols_non_tcp_raises(self):
        args = dict(
            protocol='udp',
            additional_protocols=['ftp', 'pop3']
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.additional_protocols is None

        assert str(res.exception) == "The 'additional_protocols' parameter can only be used with TCP traffic."

    def test_invalid_additional_protocols_values_raises(self):
        args = dict(
            additional_protocols=['fail']
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.additional_protocols is None

        assert str(res.exception) == "Acceptable values for the 'additional_protocols' parameter are " \
                                     "'ftp', 'imap', 'pop3', and 'smtps'. Received: 'fail'."


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch(
            'ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_topology.F5Client'
        )
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch(
            'ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_topology.sslo_version'
        )
        self.m3 = self.p3.start()
        self.m3.return_value = '7.5'

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_create_l2_out_topology_object_no_gs_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_l2_out_topo_create_generated.json')
        set_module_args(dict(
            name='l2_topo_out',
            dest='192.168.1.2%0/32',
            port=0,
            topology_type='outbound_l2',
            ssl_settings='foobar',
            vlans=['/Common/fake1'],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('sslo_gs_missing.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_l2_in_topology_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_l2_in_topo_create_generated.json')
        set_module_args(dict(
            name='l2_topo_in',
            dest='192.168.1.3%0/32',
            port=0,
            topology_type='inbound_l2',
            ssl_settings='foobar',
            vlans=['/Common/fake1'],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('sslo_gs_present.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_l3_out_topology_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_l3_out_topo_create_generated.json')
        set_module_args(dict(
            name='l3_topo_out',
            dest='192.168.1.4%0/32',
            port=0,
            topology_type='outbound_l3',
            ssl_settings='foobar',
            vlans=['/Common/fake1'],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('sslo_gs_present.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_l3_in_topology_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_l3_in_topo_create_generated.json')
        set_module_args(dict(
            name='l3_topo_in',
            dest='192.168.1.5%0/32',
            port=0,
            topology_type='inbound_l3',
            ssl_settings='foobar',
            vlans=['/Common/fake1'],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('sslo_gs_present.json'))
        )

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_expl_out_topology_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_l3_expl_topo_create_generated.json')
        set_module_args(dict(
            name='expl_topo',
            topology_type='outbound_explicit',
            proxy_ip='192.168.1.1',
            proxy_port=3211,
            security_policy='from_gui',
            ssl_settings='foobar',
            vlans=['/Common/fake1'],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('sslo_gs_present.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_delete_topology_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_topology_delete_created.json')
        set_module_args(dict(
            name='expl_topo',
            topology_type='outbound_explicit',
            state='absent',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_topology.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_l2_in_topology_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='l2_topo_in',
            dest='192.168.1.3%0/32',
            port=0,
            topology_type='inbound_l2',
            ssl_settings='foobar',
            vlans=['/Common/fake1']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        gs = dict(code=200, contents=load_fixture('sslo_gs_present.json'))
        exists = dict(code=200, contents=load_fixture('load_sslo_topo_l2_in.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_topo_l2_in_create_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.get = Mock(side_effect=[exists, gs, done])

        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_topo_l2_in_create_start.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['topology'] == 'topology_l2_inbound'
        assert results['rule'] == 'Inbound'
        assert results['dep_net'] == 'l2_network'
        assert results['dest'] == '192.168.1.3%0/32'
        assert results['port'] == 0
        assert results['vlans'] == [{'name': '/Common/fake1', 'value': '/Common/fake1'}]
        assert results['ssl_settings'] == 'ssloT_foobar'

    def test_create_l3_out_topology_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='l3_topo_out',
            dest='192.168.1.4%0/32',
            port=0,
            topology_type='outbound_l3',
            ssl_settings='foobar',
            vlans=['/Common/fake1']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        gs = dict(code=200, contents=load_fixture('sslo_gs_present.json'))
        exists = dict(code=200, contents=load_fixture('load_sslo_topo_l3_out.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_topo_l3_out_create_done.json'))

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.get = Mock(side_effect=[exists, gs, done])

        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_topo_l3_out_create_start.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['topology'] == 'topology_l3_outbound'
        assert results['rule'] == 'Outbound'
        assert results['dest'] == '192.168.1.4%0/32'
        assert results['port'] == 0
        assert results['vlans'] == [{'name': '/Common/fake1', 'value': '/Common/fake1'}]
        assert results['ssl_settings'] == 'ssloT_foobar'

    def test_create_l3_in_topology_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='l3_topo_in',
            dest='192.168.1.5%0/32',
            port=0,
            topology_type='inbound_l3',
            ssl_settings='foobar',
            vlans=['/Common/fake1']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        gs = dict(code=200, contents=load_fixture('sslo_gs_present.json'))
        exists = dict(code=200, contents=load_fixture('load_sslo_topo_l3_in.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_topo_l3_in_create_done.json'))

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.get = Mock(side_effect=[exists, gs, done])

        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_topo_l3_in_create_start.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['topology'] == 'topology_l3_inbound'
        assert results['rule'] == 'Inbound'
        assert results['dest'] == '192.168.1.5%0/32'
        assert results['port'] == 0
        assert results['vlans'] == [{'name': '/Common/fake1', 'value': '/Common/fake1'}]
        assert results['ssl_settings'] == 'ssloT_foobar'

    def test_create_expl_out_topology_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='expl_topo',
            topology_type='outbound_explicit',
            proxy_ip='192.168.1.1',
            proxy_port=3211,
            security_policy='from_gui',
            ssl_settings='foobar',
            vlans=['/Common/fake1']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        gs = dict(code=200, contents=load_fixture('sslo_gs_present.json'))
        exists = dict(code=200, contents=load_fixture('load_sslo_topo_expl.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_topo_expl_create_done.json'))

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.get = Mock(side_effect=[exists, gs, done])

        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_topo_expl_create_start.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['topology'] == 'topology_l3_explicit_proxy'
        assert results['rule'] == 'Outbound'
        assert results['proxy_type'] == 'explicit'
        assert results['proxy_ip'] == '192.168.1.1'
        assert results['proxy_port'] == 3211
        assert results['vlans'] == [{'name': '/Common/fake1', 'value': '/Common/fake1'}]
        assert results['ssl_settings'] == 'ssloT_foobar'
        assert results['security_policy'] == 'ssloP_from_gui'

    def test_vlans_parameter_missing(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='l2_topo_out',
            topology_type='inbound_l2'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == 'At least one VLAN must be defined.'

    def test_ip_family_mismatch(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='l2_topo_out',
            topology_type='inbound_l2',
            vlans=['/Common/fake'],
            source='2001:0db8:85a3:0000:0000:8a2e:0370:7334/32'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == 'Source and destination addresses must be in the same IP family.'

    def test_ip_family_mismatch_proxy(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='fake_explicit',
            topology_type='outbound_explicit',
            vlans=['/Common/fake'],
            proxy_ip='19.1.1.1',
            proxy_port=1234,
            source='2001:0db8:85a3:0000:0000:8a2e:0370:7334/32'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == 'Source and proxy addresses must be in the same IP family.'

    def test_profile_scope_public_invalid_version(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        err = "The 'primary_auth_uri', 'profile_scope_value' or 'profile_scope' are " \
              "supported on SSLO version 8.2 and above, your SSLO version is 7.5."
        set_module_args(dict(
            name='l2_topo_out',
            topology_type='inbound_l2',
            vlans=['/Common/fake'],
            profile_scope='public'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    def test_profile_scope_named_invalid_version(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        err = "The 'primary_auth_uri', 'profile_scope_value' or 'profile_scope' are " \
              "supported on SSLO version 8.2 and above, your SSLO version is 7.5."
        set_module_args(dict(
            name='l3_topo_out',
            topology_type='outbound_l3',
            vlans=['/Common/fake'],
            profile_scope='named',
            profile_scope_value='some_value',
            primary_auth_uri='/foofake'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    def test_oscp_auth_invalid_version(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        err = "The 'ocsp_auth' key is supported on SSLO version 9.0 and above, your SSLO version is 7.5."
        set_module_args(dict(
            name='l2_topo_out',
            topology_type='inbound_l2',
            vlans=['/Common/fake'],
            ocsp_auth='fake'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    def test_verify_accept_invalid_version(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        err = "The 'verify_accept' key is supported on SSLO version 9.0 and above, your SSLO version is 7.5."
        set_module_args(dict(
            name='l2_topo_out',
            topology_type='inbound_l2',
            vlans=['/Common/fake'],
            verify_accept='no'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    def test_ssl_settings_missing_l3_out(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='l3_topo_out',
            topology_type='outbound_l3',
            vlans=['/Common/fake']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == 'The Outbound L3 topology for TCP traffic requires an ssl_settings key.'

    def test_ssl_settings_invalid_protocol_udp_l3_out(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='l3_topo_out',
            topology_type='outbound_l3',
            vlans=['/Common/fake'],
            protocol='udp',
            ssl_settings='foobar'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == 'The Outbound L3 topology for UDP traffic cannot contain an ssl_settings key.'

    def test_ssl_settings_invalid_protocol_other_l3_out(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        err = 'The Outbound L3 topology for non-TCP/non-UDP traffic cannot contain an ssl_settings key.'
        set_module_args(dict(
            name='l3_topo_out',
            topology_type='outbound_l3',
            vlans=['/Common/fake'],
            protocol='other',
            ssl_settings='foobar'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    def test_security_policy_invalid_protocol_l3_out(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        err = 'The Outbound L3 topology for non-TCP/non-UDP traffic cannot contain a security_policy key.'
        set_module_args(dict(
            name='l3_topo_out',
            topology_type='outbound_l3',
            vlans=['/Common/fake'],
            protocol='other',
            security_policy='barsecure'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    @patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_topology.sslo_version')
    def test_profile_scope_value_invalid_protocol_l3_out(self, sslo):
        # Configure the arguments that would be sent to the Ansible module
        sslo.return_value = '8.2'
        err = "The 'profile_scope_value' key can only be used with an outbound L3 TCP topology."
        set_module_args(dict(
            name='l3_topo_out',
            topology_type='outbound_l3',
            vlans=['/Common/fake'],
            protocol='other',
            profile_scope_value='some_value'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    @patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_topology.sslo_version')
    def test_primary_auth_uri_invalid_protocol_l3_out(self, sslo):
        # Configure the arguments that would be sent to the Ansible module
        sslo.return_value = '8.2'
        err = "The 'primary_auth_uri' key can only be used with an outbound L3 TCP topology."
        set_module_args(dict(
            name='l3_topo_out',
            topology_type='outbound_l3',
            vlans=['/Common/fake'],
            protocol='other',
            primary_auth_uri='/fake'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    def test_ssl_settings_missing_l2_out(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='l2_topo_out',
            topology_type='outbound_l2',
            vlans=['/Common/fake']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == 'The Outbound L2 topology for TCP traffic requires an ssl_settings key.'

    def test_ssl_settings_invalid_protocol_udp_l2_out(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='l2_topo_out',
            topology_type='outbound_l2',
            vlans=['/Common/fake'],
            protocol='udp',
            ssl_settings='foobar'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == 'The Outbound L2 topology for UDP traffic cannot contain an ssl_settings key.'

    def test_ssl_settings_invalid_protocol_other_l2_out(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        err = 'The Outbound L2 topology for non-TCP/non-UDP traffic cannot contain an ssl_settings key.'
        set_module_args(dict(
            name='l2_topo_out',
            topology_type='outbound_l2',
            vlans=['/Common/fake'],
            protocol='other',
            ssl_settings='foobar'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    def test_security_policy_invalid_protocol_l2_out(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        err = 'The Outbound L2 topology for non-TCP/non-UDP traffic cannot contain a security_policy key.'
        set_module_args(dict(
            name='l2_topo_out',
            topology_type='outbound_l2',
            vlans=['/Common/fake'],
            protocol='other',
            security_policy='barsecure'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    @patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_topology.sslo_version')
    def test_profile_scope_value_invalid_protocol_l2_out(self, sslo):
        # Configure the arguments that would be sent to the Ansible module
        sslo.return_value = '8.2'
        err = "The 'profile_scope_value' key can only be used with an outbound L2 TCP topology."
        set_module_args(dict(
            name='l2_topo_out',
            topology_type='outbound_l2',
            vlans=['/Common/fake'],
            protocol='other',
            profile_scope_value='some_value'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    @patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_topology.sslo_version')
    def test_primary_auth_uri_invalid_protocol_l2_out(self, sslo):
        # Configure the arguments that would be sent to the Ansible module
        sslo.return_value = '8.2'
        err = "The 'primary_auth_uri' key can only be used with an outbound L2 TCP topology."
        set_module_args(dict(
            name='l2_topo_out',
            topology_type='outbound_l2',
            vlans=['/Common/fake'],
            protocol='other',
            primary_auth_uri='/fake'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err

    def test_proxy_ip_missing_explicit_proxy(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='explicit_out',
            topology_type='outbound_explicit',
            vlans=['/Common/fake']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == "The 'proxy_ip' is required when creating explicit proxy type topology."

    def test_security_policy_missing_explicit_proxy(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='explicit_out',
            topology_type='outbound_explicit',
            proxy_ip='191.1.1.1',
            proxy_port=1234,
            vlans=['/Common/fake']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == "The 'security_policy' is required when creating explicit proxy type topology."

    def test_proxy_ip_defined_for_non_explict_proxy_type(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        err = "The 'proxy_ip' key is only to be used with explicit proxy type, use 'dest' key instead."
        set_module_args(dict(
            name='l2_out',
            topology_type='outbound_l2',
            proxy_ip='191.1.1.1',
            proxy_port=1234,
            ssl_settings='fakesettings',
            vlans=['/Common/fake']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_together=self.spec.required_together,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.return_sslo_global = Mock(return_value=True)
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err
