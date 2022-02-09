# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_ssl import (
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
            name='fake_foo',
            client_settings=dict(
                proxy_type='forward',
                cipher_type='group',
                cipher_string='DEFAULT',
                cipher_group='/Common/fake_grp',
                cert='/Common/foocert.crt',
                key='/Common/fookey.crt',
                chain='/Common/foochain.crt',
                ca_cert='/Common/fake_cert.crt',
                ca_key='/Common/fake_key.key',
                ca_chain='/Common/chain_fake.crt',
                log_publisher='/Common/foo-logger'
            ),
            server_settings=dict(
                cipher_type='group',
                cipher_string='FOOBAR',
                cipher_group='/Common/fake_servers',
                ca_bundle='/Common/fake_ca',
                block_expired='yes',
                block_untrusted='no',
                ocsp='bar_ocsp',
                crl='fake_crl',
                log_publisher='/Common/baz-logger'
            ),
            bypass_handshake_failure='enabled',
            bypass_client_cert_failure='disabled',
            timeout=250
        )
        p = ModuleParameters(params=args)

        assert p.name == 'ssloT_fake_foo'
        assert p.client_cipher_type == 'group'
        assert p.client_cipher_string == 'DEFAULT'
        assert p.client_cipher_group == '/Common/fake_grp'
        assert p.client_cert == '/Common/foocert.crt'
        assert p.client_key == '/Common/fookey.crt'
        assert p.client_chain == '/Common/foochain.crt'
        assert p.client_ca_cert == '/Common/fake_cert.crt'
        assert p.client_ca_key == '/Common/fake_key.key'
        assert p.client_ca_chain == '/Common/chain_fake.crt'
        assert p.client_log_publisher == '/Common/foo-logger'
        assert p.server_cipher_type == 'group'
        assert p.server_cipher_string == 'FOOBAR'
        assert p.server_cipher_group == '/Common/fake_servers'
        assert p.server_ca_bundle == '/Common/fake_ca'
        assert p.block_expired is True
        assert p.block_untrusted is False
        assert p.server_ocsp == 'bar_ocsp'
        assert p.server_crl == 'fake_crl'
        assert p.server_log_publisher == '/Common/baz-logger'
        assert p.bypass_handshake_failure is True
        assert p.bypass_client_cert_failure is False
        assert p.timeout == (2, 100)

    def test_api_parameters(self):
        args = load_fixture('return_sslo_config_ssl_params.json')
        p = ApiParameters(params=args)

        assert p.proxy_type == 'forward'
        assert p.client_cipher_type == 'group'
        assert p.client_cipher_string == 'DEFAULT'
        assert p.client_cipher_group == '/Common/f5-default'
        assert p.client_cert == '/Common/default.crt'
        assert p.client_key == '/Common/default.key'
        assert p.client_chain == ''
        assert p.client_ca_cert == '/Common/default.crt'
        assert p.client_ca_key == '/Common/default.key'
        assert p.client_ca_chain == ''
        assert p.client_enable_tls13 == [{'name': 'TLSv1.3', 'value': 'TLSv1.3'}]
        assert p.client_log_publisher == '/Common/sys-ssl-publisher'
        assert p.server_cipher_type == 'group'
        assert p.server_cipher_string == 'DEFAULT'
        assert p.server_cipher_group == '/Common/f5-default'
        assert p.server_ca_bundle == '/Common/ca-bundle.crt'
        assert p.server_enable_tls13 == [{'name': 'TLSv1.3', 'value': 'TLSv1.3'}]
        assert p.block_expired is True
        assert p.block_untrusted is True
        assert p.server_ocsp == ''
        assert p.server_crl == ''
        assert p.server_log_publisher == '/Common/sys-ssl-publisher'
        assert p.bypass_handshake_failure is True
        assert p.bypass_client_cert_failure is False


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_ssl.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_ssl.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '9.0'

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_create_ssl_object_rev_proxy_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_ssl_create_rev_proxy_generated.json')
        set_module_args(dict(
            name='foobar',
            client_settings=dict(
                proxy_type='reverse',
                cert='/Common/default.crt',
                key='/Common/default.key'
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

    def test_create_ssl_object_fwd_proxy_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_ssl_create_fwd_proxy_generated.json')
        set_module_args(dict(
            name='barfoo',
            client_settings=dict(
                proxy_type='forward',
                cipher_type='group',
                cipher_group='/Common/f5-default',
                ca_cert='/Common/default.crt',
                ca_key='/Common/default.key',
                alpn=True
            ),
            server_settings=dict(
                cipher_type='group',
                cipher_group='/Common/f5-default'
            ),
            bypass_handshake_failure=True,
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

    def test_modify_ssl_object_rev_proxy_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_ssl_modify_rev_proxy_generated.json')
        set_module_args(dict(
            name='foobar',
            client_settings=dict(
                proxy_type='reverse',
                cert='/Common/sslo_test.crt',
                key='/Common/sslo_test.key'
            ),
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_ssl_rev_proxy.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_modify_ssl_object_fwd_proxy_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_ssl_modify_fwd_proxy_generated.json')
        set_module_args(dict(
            name='barfoo',
            client_settings=dict(
                proxy_type='forward',
                ca_cert='/Common/sslo_test.crt',
                ca_key='/Common/sslo_test.key'
            ),
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_ssl_fwd_proxy.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_delete_ssl_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_ssl_delete_generated.json')
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
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_sslo_ssl_rev_proxy.json')))

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_ssl_object_rev_proxy(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='foobar',
            client_settings=dict(
                proxy_type='reverse',
                cert='/Common/default.crt',
                key='/Common/default.key'
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_ssl_create_rev_proxy_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_ssl_create_rev_proxy_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['client_settings'] == {
            'proxy_type': 'reverse', 'cert': '/Common/default.crt', 'key': '/Common/default.key'
        }

    def test_create_ssl_object_fwd_proxy(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='barfoo',
            client_settings=dict(
                proxy_type='forward',
                cipher_type='group',
                cipher_group='/Common/f5-default',
                ca_cert='/Common/default.crt',
                ca_key='/Common/default.key',
                alpn=True
            ),
            server_settings=dict(
                cipher_type='group',
                cipher_group='/Common/f5-default'
            ),
            bypass_handshake_failure=True
        ))
        client = {
            'proxy_type': 'forward', 'cipher_type': 'group', 'cipher_group': '/Common/f5-default',
            'alpn': True, 'ca_cert': '/Common/default.crt', 'ca_key': '/Common/default.key'
        }
        server = {'cipher_type': 'group', 'cipher_group': '/Common/f5-default'}
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_ssl_create_fwd_proxy_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_ssl_create_fwd_proxy_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['client_settings'] == client
        assert results['server_settings'] == server
        assert results['bypass_handshake_failure'] is True

    def test_modify_ssl_object_rev_proxy(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='foobar',
            client_settings=dict(
                proxy_type='reverse',
                cert='/Common/sslo_test.crt',
                key='/Common/sslo_test.key'
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_ssl_rev_proxy.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_ssl_modify_rev_proxy_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_ssl_modify_rev_proxy_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['client_settings'] == {'cert': '/Common/sslo_test.crt', 'key': '/Common/sslo_test.key'}

    def test_modify_ssl_object_fwd_proxy(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='barfoo',
            client_settings=dict(
                proxy_type='forward',
                ca_cert='/Common/sslo_test.crt',
                ca_key='/Common/sslo_test.key'
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_ssl_fwd_proxy.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_ssl_modify_fwd_proxy_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_ssl_modify_fwd_proxy_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['client_settings'] == {'ca_cert': '/Common/sslo_test.crt', 'ca_key': '/Common/sslo_test.key'}

    def test_delete_ssl_object(self, *args):
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

        exists = dict(code=200, contents=load_fixture('load_sslo_ssl_rev_proxy.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_ssl_delete_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_ssl_delete_start.json')))
        mm.client.get = Mock(side_effect=[exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
