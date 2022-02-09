# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_authentication import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
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
            name='fake_foo',
            ocsp=dict(
                fqdn='baz.bar.net',
                dest='192.168.1.1/32',
                source='10.101.1.0/24',
                ssl_profile='some_ssl',
                vlans=['/Common/vlan1', '/Common/vlan2'],
                port=2341,
                http_profile='/Common/http_sslo',
                tcp_settings_client='/Common/fake_client',
                tcp_settings_server='/Common/fake_server',
                existing_ocsp='/Common/exist_fake',
                ocsp_max_age=34665,
                ocsp_nonce=False
            )
        )
        p = ModuleParameters(params=args)

        assert p.name == 'ssloA_fake_foo'
        assert p.ocsp_fqdn == 'baz.bar.net'
        assert p.ocsp_dest == '192.168.1.1%0/32'
        assert p.ocsp_source == '10.101.1.0%0/24'
        assert p.ocsp_ssl_profile == 'ssloT_some_ssl'
        assert p.ocsp_vlans == [{'name': '/Common/vlan1', 'value': '/Common/vlan1'},
                                {'name': '/Common/vlan2', 'value': '/Common/vlan2'}]
        assert p.ocsp_port == 2341
        assert p.ocsp_http_profile == '/Common/http_sslo'
        assert p.ocsp_tcp_settings_client == '/Common/fake_client'
        assert p.ocsp_tcp_settings_server == '/Common/fake_server'
        assert p.existing_ocsp == '/Common/exist_fake'
        assert p.ocsp_max_age == 34665
        assert p.ocsp_nonce == 'disabled'

    def test_api_parameters(self):
        args = load_fixture('return_sslo_config_auth_params.json')
        p = ApiParameters(params=args)

        assert p.ocsp_fqdn == 'baz.bar.net'
        assert p.ocsp_dest == '192.168.1.1%0/32'
        assert p.ocsp_http_profile == '/Common/http'
        assert p.ocsp_max_age == 604800
        assert p.ocsp_port == 80
        assert p.ocsp_source == '0.0.0.0%0/0'
        assert p.ocsp_ssl_profile == 'ssloT_fake_ssl_1'
        assert p.ocsp_tcp_settings_client == '/Common/f5-tcp-wan'
        assert p.ocsp_tcp_settings_server == '/Common/f5-tcp-lan'
        assert p.ocsp_vlans == [{'name': '/Common/vlan1', 'value': '/Common/vlan1'},
                                {'name': '/Common/vlan2', 'value': '/Common/vlan2'}]
        assert p.use_existing is False
        assert p.existing_ocsp == ''
        assert p.ocsp_nonce == 'enabled'

    def test_invalid_source_param(self):
        args = dict(
            name='fail',
            ocsp=dict(
                source='10.10.10.0'
            )
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.ocsp_source is None
        assert str(res.exception) == 'Source address must contain a subnet (CIDR) value <= 32.'

    def test_invalid_dst_param(self):
        args = dict(
            name='fail',
            ocsp=dict(
                dest='192.168.1.1'
            )
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.ocsp_dest == '192.168.1.1'
        assert str(res.exception) == 'Destination address must contain a subnet (CIDR) value <= 32.'

    def test_invalid_port_param(self):
        args = dict(
            name='fail',
            ocsp=dict(
                port=99999
            )
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.ocsp_port == 99999
        assert str(res.exception) == 'A defined port must be an integer between 0 and 65535.'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_authentication.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_authentication.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '9.0'

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_create_authentication_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_auth_create_generated.json')
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                fqdn='baz.bar.net',
                dest='192.168.1.1/32',
                ssl_profile='fake_ssl_1',
                vlans=['/Common/vlan1', '/Common/vlan2']
            ),
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

    def test_modify_authentication_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_auth_modify_generated.json')
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                vlans=['/Common/client-vlan', '/Common/dlp-vlan'],
                ssl_profile='fake_ssl',
            ),
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_config_auth.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_delete_authentication_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_auth_delete_generated.json')
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
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_sslo_config_auth.json')))

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_authentication_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                fqdn='baz.bar.net',
                dest='192.168.1.1/32',
                ssl_profile='fake_ssl_1',
                vlans=['/Common/vlan1', '/Common/vlan2']
            ),
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_auth_create_start.json')))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('reply_sslo_auth_create_done.json')))

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['ocsp']['fqdn'] == 'baz.bar.net'
        assert results['ocsp']['dest'] == '192.168.1.1%0/32'
        assert results['ocsp']['ssl_profile'] == 'fake_ssl_1'
        assert results['ocsp']['vlans'] == [{'name': '/Common/vlan1', 'value': '/Common/vlan1'},
                                            {'name': '/Common/vlan2', 'value': '/Common/vlan2'}]

    def test_modify_authentication_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                vlans=['/Common/client-vlan', '/Common/dlp-vlan'],
                ssl_profile='fake_ssl',
            ),
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,

        )
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_config_auth.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_auth_modify_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_auth_modify_start.json')))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['ocsp']['ssl_profile'] == 'fake_ssl'
        assert results['ocsp']['vlans'] == [{'name': '/Common/client-vlan', 'value': '/Common/client-vlan'},
                                            {'name': '/Common/dlp-vlan', 'value': '/Common/dlp-vlan'}]

    def test_delete_authentication_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='foobar',
            state='absent'
        ),
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,

        )
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_config_auth.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_auth_delete_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_auth_delete_start.json')))
        mm.client.get = Mock(side_effect=[exists, done])

        results = mm.exec_module()
        assert results['changed'] is True

    def test_modify_authentication_object_failure(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        err = 'MODIFY operation error: 1841b2a3-5279-4472-b013-b80e8e771538 : ' \
              '[OrchestratorConfigProcessor] Deployment failed for Error: [HAAwareICRDeployProcessor] ' \
              'Error: transaction failed:01020036:3: ' \
              'The requested profile (/Common/ssloT_fake_ssl.app/ssloT_fake_ssl-cssl-vht) was not found.'
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                vlans=['/Common/client-vlan', '/Common/dlp-vlan'],
                ssl_profile='fake_ssl',
            ),
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,

        )
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_config_auth.json'))
        error = dict(code=200, contents=load_fixture('reply_sslo_auth_modify_failure_test_error.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(code=200, contents=load_fixture('reply_sslo_auth_modify_failure_test_start.json')))
        mm.client.get = Mock(side_effect=[exists, exists, error])
        mm.client.delete = Mock(return_value=dict(code=200, contents=load_fixture('reply_sslo_auth_failed_operation_delete.json')))

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err
        assert mm.client.delete.call_count == 1
        assert mm.client.delete.call_args[0][0] == '/mgmt/shared/iapp/blocks/1841b2a3-5279-4472-b013-b80e8e771538'
