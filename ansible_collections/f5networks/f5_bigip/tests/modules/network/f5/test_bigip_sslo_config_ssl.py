# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
from copy import deepcopy
from types import SimpleNamespace

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_sslo_config_ssl as ssl_module
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_ssl import (
    ModuleParameters, ApiParameters, ArgumentSpec, Difference, ModuleManager, F5ModuleError
)
from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch, MagicMock
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import AnsibleFailJson, fail_json, set_module_args


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
    def setUp(self):
        fixture_data.clear()

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
                block_expired='drop',
                block_untrusted='drop',
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
        assert p.block_expired == 'drop'
        assert p.block_untrusted == 'drop'
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
        assert p.client_ssl_options == [{'name': 'TLSv1.3', 'value': 'TLSv1.3'}]
        assert p.client_log_publisher == '/Common/sys-ssl-publisher'
        assert p.server_cipher_type == 'group'
        assert p.server_cipher_string == 'DEFAULT'
        assert p.server_cipher_group == '/Common/f5-default'
        assert p.server_ca_bundle == '/Common/ca-bundle.crt'
        assert p.server_ssl_options == [{'name': 'TLSv1.3', 'value': 'TLSv1.3'}]
        assert p.block_expired == 'drop'
        assert p.block_untrusted == 'drop'
        assert p.server_ocsp == ''
        assert p.server_crl == ''
        assert p.server_log_publisher == '/Common/sys-ssl-publisher'
        assert p.bypass_handshake_failure is True
        assert p.bypass_client_cert_failure is False

    def test_api_param_block_expired_untrusted(self):
        args = deepcopy(load_fixture('return_sslo_config_ssl_params.json'))

        p = ApiParameters(params=args)
        self.assertEqual(p.block_expired, 'drop')
        self.assertEqual(p.block_untrusted, 'drop')

        args['serverSettings']['expiredCertificates'] = 'ignore'
        args['serverSettings']['untrustedCertificates'] = 'ignore'
        p = ApiParameters(params=args)
        self.assertEqual(p.block_expired, 'ignore')
        self.assertEqual(p.block_untrusted, 'ignore')

        args['serverSettings']['expiredCertificates'] = False
        args['serverSettings']['untrustedCertificates'] = False
        p = ApiParameters(params=args)
        self.assertEqual(p.block_expired, 'ignore')
        self.assertEqual(p.block_untrusted, 'ignore')

        args['serverSettings']['expiredCertificates'] = True
        args['serverSettings']['untrustedCertificates'] = True
        p = ApiParameters(params=args)
        self.assertEqual(p.block_expired, 'drop')
        self.assertEqual(p.block_untrusted, 'drop')

    def test_proxy_type_required(self):
        params = ModuleParameters(params=dict(client_settings={}))

        with self.assertRaisesRegex(F5ModuleError, "'proxy_type' parameter is required"):
            params.proxy_type

    def test_alpn_rejects_reverse_proxy(self):
        params = ModuleParameters(params=dict(client_settings=dict(proxy_type='reverse', alpn=True)))

        with self.assertRaisesRegex(F5ModuleError, "'alpn' parameter can only be used with 'forward'"):
            params.alpn

    def test_timeout_rejects_values_outside_range(self):
        for timeout in (9, 1801):
            params = ModuleParameters(params=dict(timeout=timeout))

            with self.assertRaisesRegex(F5ModuleError, 'Timeout value must be between 10 and 1800 seconds'):
                params.timeout

    def test_proxy_type_cannot_be_changed(self):
        want = ModuleParameters(params=dict(client_settings=dict(proxy_type='forward')))
        have = ApiParameters(params=dict(clientSettings=dict(caCertKeyChain=[])))

        with self.assertRaisesRegex(F5ModuleError, "'proxy_type' parameter cannot be changed"):
            Difference(want, have).proxy_type


class TestArgumentSpec(unittest.TestCase):
    def setUp(self):
        fixture_data.clear()
        self.spec = ArgumentSpec()

    def assert_invalid_parameters(self, client_settings=None, server_settings=None):
        args = dict(name='foobar')
        if client_settings is not None:
            args['client_settings'] = client_settings
        if server_settings is not None:
            args['server_settings'] = server_settings
        set_module_args(args)

        with patch.object(AnsibleModule, 'fail_json', fail_json), \
                self.assertRaises(AnsibleFailJson):
            AnsibleModule(
                argument_spec=self.spec.argument_spec,
                supports_check_mode=self.spec.supports_check_mode,
            )

    def test_client_certificate_and_key_are_required_together(self):
        self.assert_invalid_parameters(client_settings=dict(proxy_type='reverse', cert='/Common/default.crt'))
        self.assert_invalid_parameters(client_settings=dict(proxy_type='reverse', key='/Common/default.key'))

    def test_forward_ca_certificate_and_key_are_required_together(self):
        self.assert_invalid_parameters(client_settings=dict(proxy_type='forward', ca_cert='/Common/default.crt'))
        self.assert_invalid_parameters(client_settings=dict(proxy_type='forward', ca_key='/Common/default.key'))

    def test_client_cipher_group_validation(self):
        self.assert_invalid_parameters(client_settings=dict(proxy_type='reverse', cipher_type='group'))
        self.assert_invalid_parameters(client_settings=dict(
            proxy_type='reverse', cipher_type='group', cipher_string='DEFAULT', cipher_group='/Common/f5-default'
        ))

    def test_server_cipher_group_validation(self):
        self.assert_invalid_parameters(server_settings=dict(cipher_type='group'))
        self.assert_invalid_parameters(server_settings=dict(
            cipher_type='group', cipher_string='DEFAULT', cipher_group='/Common/f5-default'
        ))


class TestManager(unittest.TestCase):
    def setUp(self):
        fixture_data.clear()
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_ssl.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_ssl.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '9.0'
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_ssl.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

    def create_manager(self, args):
        set_module_args(args)
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        return ModuleManager(module=module)

    def test_reverse_proxy_is_idempotent(self):
        mm = self.create_manager(dict(
            name='foobar',
            client_settings=dict(proxy_type='reverse', cert='/Common/default.crt', key='/Common/default.key')
        ))
        current = dict(code=200, contents=deepcopy(load_fixture('load_sslo_ssl_rev_proxy.json')))
        mm.client.get = Mock(side_effect=[current, current])

        results = mm.exec_module()

        assert results['changed'] is False
        mm.client.post.assert_not_called()

    def test_forward_proxy_is_idempotent(self):
        mm = self.create_manager(dict(
            name='barfoo',
            client_settings=dict(
                proxy_type='forward', cipher_type='group', cipher_group='/Common/f5-default',
                ca_cert='/Common/default.crt', ca_key='/Common/default.key', alpn=True
            ),
            server_settings=dict(cipher_type='group', cipher_group='/Common/f5-default'),
            bypass_handshake_failure=True
        ))
        current = dict(code=200, contents=deepcopy(load_fixture('load_sslo_ssl_fwd_proxy.json')))
        mm.client.get = Mock(side_effect=[current, current])

        results = mm.exec_module()

        assert results['changed'] is False
        mm.client.post.assert_not_called()

    def test_unsupported_sslo_version(self):
        self.m3.return_value = '99.0'
        mm = self.create_manager(dict(name='foobar', client_settings=dict(proxy_type='reverse')))

        with self.assertRaisesRegex(F5ModuleError, 'Unsupported SSL Orchestrator version'):
            mm.check_sslo_version()

    def test_version_specific_parameters_require_sslo_9(self):
        mm = self.create_manager(dict(name='foobar', client_settings=dict(proxy_type='reverse')))
        mm.version = '8.0'
        cases = (
            ('alpn', True, "'alpn' parameter"),
            ('sni', dict(sni_default=True), "'sni' parameter"),
            ('client_log_publisher', '/Common/client-logger', "'client_log_publisher' parameter"),
            ('server_log_publisher', '/Common/server-logger', "'server_log_publisher' parameter"),
        )

        for field, value, message in cases:
            changes = dict(alpn=None, sni=None, client_log_publisher=None, server_log_publisher=None)
            changes[field] = value
            mm.changes = SimpleNamespace(**changes)

            with self.assertRaisesRegex(F5ModuleError, message):
                mm.check_version_specific_parameters()

    def test_exists_raises_for_api_error(self):
        mm = self.create_manager(dict(name='foobar', client_settings=dict(proxy_type='reverse')))
        mm.client.get.return_value = dict(code=500, contents='exists failed')

        with self.assertRaisesRegex(F5ModuleError, 'exists failed'):
            mm.exists()

    def test_create_on_device_raises_for_api_error(self):
        mm = self.create_manager(dict(name='foobar', client_settings=dict(proxy_type='reverse')))
        mm.version = '9.0'
        mm.operation = 'CREATE'
        mm._set_changed_options()
        mm.client.post.return_value = dict(code=500, contents='create failed')

        with self.assertRaisesRegex(F5ModuleError, 'create failed'):
            mm.create_on_device()

    def test_update_on_device_raises_for_api_error(self):
        mm = self.create_manager(dict(name='foobar', client_settings=dict(proxy_type='reverse')))
        mm.version = '9.0'
        mm.operation = 'MODIFY'
        mm.block_id = '1234'
        mm.changes = MagicMock()
        mm.changes.to_return.return_value = {}
        mm.add_missing_options = Mock(return_value={})
        mm.client.post.return_value = dict(code=500, contents='update failed')

        with patch.object(ssl_module, 'process_json', return_value={}):
            with self.assertRaisesRegex(F5ModuleError, 'update failed'):
                mm.update_on_device()

    def test_remove_from_device_raises_for_api_error(self):
        mm = self.create_manager(dict(name='foobar', state='absent'))
        mm.version = '9.0'
        mm.operation = 'DELETE'
        mm.block_id = '1234'
        mm.client.post.return_value = dict(code=500, contents='remove failed')

        with self.assertRaisesRegex(F5ModuleError, 'remove failed'):
            mm.remove_from_device()

    def test_read_current_raises_for_api_error(self):
        mm = self.create_manager(dict(name='foobar', client_settings=dict(proxy_type='reverse')))
        mm.client.get.return_value = dict(code=500, contents='read failed')

        with self.assertRaisesRegex(F5ModuleError, 'read failed'):
            mm.read_current_from_device()

    def test_read_current_raises_when_object_is_missing(self):
        mm = self.create_manager(dict(name='foobar', client_settings=dict(proxy_type='reverse')))
        mm.client.get.return_value = dict(code=200, contents={'items': []})

        with self.assertRaisesRegex(F5ModuleError, r"'items': \[\]"):
            mm.read_current_from_device()

    def test_check_task_raises_for_api_error(self):
        mm = self.create_manager(dict(name='foobar', client_settings=dict(proxy_type='reverse')))
        mm.client.get.return_value = dict(code=500, contents='task failed')

        with self.assertRaisesRegex(F5ModuleError, 'task failed'):
            mm._check_task_on_device('1234')

    def test_wait_for_task_raises_for_error_state(self):
        mm = self.create_manager(dict(name='foobar', client_settings=dict(proxy_type='reverse')))
        mm.operation = 'CREATE'
        mm._check_task_on_device = Mock(return_value=dict(state='ERROR', error='deployment failed'))
        mm.client.delete.return_value = dict(code=200, contents={})

        with self.assertRaisesRegex(F5ModuleError, 'CREATE operation error: 1234 : deployment failed'):
            mm.wait_for_task('1234')

        mm.client.delete.assert_called_once()

    def test_wait_for_task_raises_on_timeout(self):
        mm = self.create_manager(dict(
            name='foobar', timeout=10, client_settings=dict(proxy_type='reverse')
        ))
        mm._check_task_on_device = Mock(return_value=dict(state='RUNNING'))

        with self.assertRaisesRegex(F5ModuleError, 'Module timeout reached'):
            mm.wait_for_task('1234')

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

        exists = dict(code=200, contents=deepcopy(load_fixture('load_sslo_ssl_rev_proxy.json')))
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

        exists = dict(code=200, contents=deepcopy(load_fixture('load_sslo_ssl_fwd_proxy.json')))
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
        server = {
            'cipher_type': 'group', 'cipher_group': '/Common/f5-default', 'block_expired': 'drop',
            'block_untrusted': 'drop'
        }
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

        exists = dict(code=200, contents=deepcopy(load_fixture('load_sslo_ssl_rev_proxy.json')))
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


class TestMain(unittest.TestCase):
    def setUp(self):
        fixture_data.clear()
        set_module_args(dict(name='foobar', client_settings=dict(proxy_type='reverse')))

    def tearDown(self):
        pass

    @patch.object(ssl_module, 'Connection')
    @patch.object(ssl_module, 'ModuleManager')
    @patch.object(ssl_module, 'AnsibleModule')
    def test_main_function_success(self, module, manager, connection):
        module.return_value._socket_path = '/tmp/socket'
        manager.return_value.exec_module.return_value = dict(changed=False)

        ssl_module.main()

        connection.assert_called_once_with('/tmp/socket')
        module.return_value.exit_json.assert_called_once_with(changed=False)

    @patch.object(ssl_module, 'Connection')
    @patch.object(ssl_module, 'ModuleManager')
    @patch.object(ssl_module, 'AnsibleModule')
    def test_main_function_failed(self, module, manager, connection):
        module.return_value._socket_path = '/tmp/socket'
        manager.return_value.exec_module.side_effect = F5ModuleError('module failed')

        ssl_module.main()

        connection.assert_called_once_with('/tmp/socket')
        module.return_value.fail_json.assert_called_once_with(msg='module failed')
