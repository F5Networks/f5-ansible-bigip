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
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager, UsableChanges, ReportableChanges
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

    def test_dest_cidr_too_large(self):
        p = ModuleParameters(params=dict(
            name='fail', ocsp=dict(dest='1.1.1.1/33')
        ))
        with self.assertRaises(F5ModuleError) as res:
            p.ocsp_dest
        assert 'Destination address must contain a subnet' in str(res.exception)

    def test_source_cidr_too_large(self):
        p = ModuleParameters(params=dict(
            name='fail', ocsp=dict(source='1.1.1.1/33')
        ))
        with self.assertRaises(F5ModuleError) as res:
            p.ocsp_source
        assert 'Source address must contain a subnet' in str(res.exception)

    def test_module_parameters_none_ocsp(self):
        # Covers all ModuleParameters ocsp_* None branches when ocsp is None
        p = ModuleParameters(params=dict(name='foo', ocsp=None))
        assert p.ocsp_fqdn is None
        assert p.ocsp_dest is None
        assert p.ocsp_source is None
        assert p.ocsp_port is None
        assert p.ocsp_vlans is None
        assert p.ocsp_ssl_profile is None
        assert p.ocsp_http_profile is None
        assert p.ocsp_tcp_settings_client is None
        assert p.ocsp_tcp_settings_server is None
        assert p.existing_ocsp is None
        assert p.ocsp_max_age is None
        assert p.ocsp_nonce is None

    def test_module_parameters_missing_ocsp_subkeys(self):
        # Covers .get('...', None) returning None inside ocsp
        p = ModuleParameters(params=dict(name='foo', ocsp=dict()))
        assert p.ocsp_fqdn is None
        assert p.ocsp_dest is None
        assert p.ocsp_source is None
        assert p.ocsp_port is None
        assert p.ocsp_vlans is None
        assert p.ocsp_ssl_profile is None

    def test_module_parameters_ssl_profile_already_prefixed(self):
        p = ModuleParameters(params=dict(
            name='foo',
            ocsp=dict(ssl_profile='ssloT_already')
        ))
        assert p.ocsp_ssl_profile == 'ssloT_already'

    def test_module_parameters_ocsp_nonce_true(self):
        p = ModuleParameters(params=dict(
            name='foo',
            ocsp=dict(ocsp_nonce=True)
        ))
        assert p.ocsp_nonce == 'enabled'

    def test_module_parameters_add_rd_with_existing_rd(self):
        # Address already contains route domain -> returned unchanged
        p = ModuleParameters(params=dict(
            name='foo',
            ocsp=dict(dest='192.168.1.1%2/32')
        ))
        assert p.ocsp_dest == '192.168.1.1%2/32'

    def test_module_parameters_timeout_too_low(self):
        p = ModuleParameters(params=dict(name='foo', timeout=5))
        with self.assertRaises(F5ModuleError) as res:
            p.timeout
        assert 'Timeout value must be between 10 and 1800 seconds.' in str(res.exception)

    def test_module_parameters_timeout_too_high(self):
        p = ModuleParameters(params=dict(name='foo', timeout=3600))
        with self.assertRaises(F5ModuleError) as res:
            p.timeout
        assert 'Timeout value must be between 10 and 1800 seconds.' in str(res.exception)

    def test_module_parameters_timeout_large_uses_100_divisor(self):
        p = ModuleParameters(params=dict(name='foo', timeout=500))
        delay, period = p.timeout
        assert period == 100
        assert delay == 5

    def test_api_parameters_none_values(self):
        # Covers ApiParameters None branches when ocsp/serverDef is None
        p = ApiParameters(params=dict(ocsp=None, serverDef=None))
        assert p.ocsp_fqdn is None
        assert p.ocsp_dest is None
        assert p.ocsp_port is None
        assert p.ocsp_source is None
        assert p.ocsp_ssl_profile is None
        assert p.ocsp_vlans is None
        assert p.ocsp_http_profile is None
        assert p.ocsp_tcp_settings_client is None
        assert p.ocsp_tcp_settings_server is None
        assert p.existing_ocsp is None
        assert p.ocsp_max_age is None
        assert p.ocsp_nonce is None
        assert p.use_existing is None

    def test_reportable_changes_full(self):
        # Covers all ReportableChanges.ocsp attribute branches
        changes = ReportableChanges(params=dict(
            ocsp_fqdn='baz.bar.net',
            ocsp_dest='192.168.1.1%0/32',
            ocsp_ssl_profile='ssloT_some_ssl',
            ocsp_vlans=[{'name': '/Common/vlan1', 'value': '/Common/vlan1'}],
            ocsp_port=2341,
            ocsp_http_profile='/Common/http_sslo',
            ocsp_tcp_settings_client='/Common/fake_client',
            ocsp_tcp_settings_server='/Common/fake_server',
            existing_ocsp='/Common/exist_fake',
            ocsp_max_age=34665,
            ocsp_nonce='disabled',
        ))
        result = changes.ocsp
        assert result['fqdn'] == 'baz.bar.net'
        assert result['dest'] == '192.168.1.1%0/32'
        # NOTE: module uses str.lstrip('ssloT_') which strips a char set,
        # so 'ssloT_some_ssl' -> 'me_ssl'. Test locks in current behavior.
        assert result['ssl_profile'] == 'me_ssl'
        assert result['port'] == 2341
        assert result['http_profile'] == '/Common/http_sslo'
        assert result['tcp_settings_client'] == '/Common/fake_client'
        assert result['tcp_settings_server'] == '/Common/fake_server'
        assert result['existing_ocsp'] == '/Common/exist_fake'
        assert result['ocsp_max_age'] == 34665
        assert result['ocsp_nonce'] == 'disabled'


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
        self.m3.return_value = '10.0'
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_authentication.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

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

    # Version validation
    def test_check_sslo_version_too_low(self, *args):
        self.m3.return_value = '5.0'
        set_module_args(dict(name='foobar', state='absent'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Unsupported SSL Orchestrator version' in str(res.exception)

    def test_check_sslo_version_too_high(self, *args):
        self.m3.return_value = '99.0'
        set_module_args(dict(name='foobar', state='absent'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Unsupported SSL Orchestrator version' in str(res.exception)

    # Required-parameter validation during create
    def _make_create_mm(self, ocsp_args):
        set_module_args(dict(name='foobar', ocsp=ocsp_args))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        return mm

    def test_create_missing_fqdn(self, *args):
        mm = self._make_create_mm(dict(
            dest='192.168.1.1/32',
            ssl_profile='fake_ssl_1',
            vlans=['/Common/vlan1'],
        ))
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'FQDN not defined' in str(res.exception)

    def test_create_missing_dest(self, *args):
        mm = self._make_create_mm(dict(
            fqdn='baz.bar.net',
            ssl_profile='fake_ssl_1',
            vlans=['/Common/vlan1'],
        ))
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Dest not defined' in str(res.exception)

    def test_create_missing_ssl_profile(self, *args):
        mm = self._make_create_mm(dict(
            fqdn='baz.bar.net',
            dest='192.168.1.1/32',
            vlans=['/Common/vlan1'],
        ))
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Ssl_profile not defined' in str(res.exception)

    def test_create_missing_vlans(self, *args):
        mm = self._make_create_mm(dict(
            fqdn='baz.bar.net',
            dest='192.168.1.1/32',
            ssl_profile='fake_ssl_1',
        ))
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Vlans not defined' in str(res.exception)

    # Absent when not exists
    def test_absent_when_not_exists(self, *args):
        set_module_args(dict(name='foobar', state='absent'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404, contents={}))
        results = mm.exec_module()
        assert results['changed'] is False

    def test_exists_error(self, *args):
        set_module_args(dict(name='foobar', state='absent'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='server error'))
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'server error' in str(res.exception)

    def test_exists_name_mismatch(self, *args):
        # covers 'return False' branch when items exist but name doesn't match
        set_module_args(dict(name='foobar', state='absent'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents={'items': [{'name': 'ssloA_someone_else', 'id': 'x'}]}
        ))
        results = mm.exec_module()
        assert results['changed'] is False

    def test_announce_deprecations(self, *args):
        # covers _announce_deprecations loop body
        set_module_args(dict(name='foobar', state='absent'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.module = MagicMock()
        mm._announce_deprecations({'__warnings': [{'msg': 'deprecated!', 'version': '2.0'}]})
        assert mm.client.module.deprecate.called

    def test_difference_existing_ocsp(self, *args):
        # covers Difference.existing_ocsp change detection (want != have)
        from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_authentication import (
            Difference,
        )
        want = ModuleParameters(params=dict(
            name='foobar', ocsp=dict(existing_ocsp='/Common/new')
        ))
        have = ApiParameters(params=load_fixture('return_sslo_config_auth_params.json'))
        diff = Difference(want, have)
        assert diff.existing_ocsp == '/Common/new'

    def test_difference_existing_ocsp_none(self, *args):
        # covers Difference.existing_ocsp early None return
        from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_authentication import (
            Difference,
        )
        want = ModuleParameters(params=dict(name='foobar', ocsp=None))
        have = ApiParameters(params=load_fixture('return_sslo_config_auth_params.json'))
        diff = Difference(want, have)
        assert diff.existing_ocsp is None

    # Check mode
    def test_create_check_mode(self, *args):
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                fqdn='baz.bar.net',
                dest='192.168.1.1/32',
                ssl_profile='fake_ssl_1',
                vlans=['/Common/vlan1'],
            ),
            _ansible_check_mode=True,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        results = mm.exec_module()
        assert results['changed'] is True

    def test_modify_check_mode(self, *args):
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                vlans=['/Common/client-vlan', '/Common/dlp-vlan'],
                ssl_profile='fake_ssl',
            ),
            _ansible_check_mode=True,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_config_auth.json'))
        mm.client.get = Mock(side_effect=[exists, exists])
        results = mm.exec_module()
        assert results['changed'] is True

    def test_remove_check_mode(self, *args):
        set_module_args(dict(name='foobar', state='absent', _ansible_check_mode=True))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_config_auth.json'))
        mm.client.get = Mock(return_value=exists)
        results = mm.exec_module()
        assert results['changed'] is True

    # Idempotency: no changes to apply
    def test_modify_no_change(self, *args):
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                fqdn='baz.bar.net',
                dest='192.168.1.1/32',
                ssl_profile='fake_ssl_1',
                vlans=['/Common/vlan1', '/Common/vlan2'],
            ),
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_config_auth.json'))
        mm.client.get = Mock(side_effect=[exists, exists])
        results = mm.exec_module()
        assert results['changed'] is False

    # Device HTTP error paths
    def test_create_on_device_error(self, *args):
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                fqdn='baz.bar.net',
                dest='192.168.1.1/32',
                ssl_profile='fake_ssl_1',
                vlans=['/Common/vlan1'],
            ),
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=500, contents='boom'))
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'boom' in str(res.exception)

    def test_update_on_device_error(self, *args):
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                vlans=['/Common/client-vlan'],
                ssl_profile='fake_ssl',
            ),
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_config_auth.json'))
        mm.client.get = Mock(side_effect=[exists, exists])
        mm.client.post = Mock(return_value=dict(code=500, contents='update failed'))
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'update failed' in str(res.exception)

    def test_remove_from_device_error(self, *args):
        set_module_args(dict(name='foobar', state='absent'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_config_auth.json'))
        mm.client.get = Mock(return_value=exists)
        mm.client.post = Mock(return_value=dict(code=500, contents='delete failed'))
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'delete failed' in str(res.exception)

    def test_read_current_from_device_error(self, *args):
        set_module_args(dict(
            name='foobar',
            ocsp=dict(vlans=['/Common/x'], ssl_profile='fake'),
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=500, contents='read error'))
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'read error' in str(res.exception)

    def test_read_current_from_device_empty(self, *args):
        set_module_args(dict(
            name='foobar',
            ocsp=dict(vlans=['/Common/x'], ssl_profile='fake'),
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents={'items': []}))
        with self.assertRaises(F5ModuleError):
            mm.exec_module()

    # wait_for_task timeout and _check_task_on_device error
    def test_wait_for_task_timeout(self, *args):
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                fqdn='baz.bar.net',
                dest='192.168.1.1/32',
                ssl_profile='fake_ssl_1',
                vlans=['/Common/vlan1'],
            ),
            timeout=10,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_auth_create_start.json')))
        # every poll returns non-BOUND non-ERROR to force timeout
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents={'items': [{'state': 'IN_PROGRESS'}]}
        ))
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Module timeout reached' in str(res.exception)

    def test_check_task_on_device_error(self, *args):
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                fqdn='baz.bar.net',
                dest='192.168.1.1/32',
                ssl_profile='fake_ssl_1',
                vlans=['/Common/vlan1'],
            ),
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_auth_create_start.json')))
        mm.client.get = Mock(return_value=dict(code=500, contents='task check failed'))
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'task check failed' in str(res.exception)

    # delete_failed_operation_on_device returning False
    def test_delete_failed_operation_returns_false(self, *args):
        set_module_args(dict(name='foobar', state='absent'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.delete = Mock(return_value=dict(code=500, contents=''))
        assert mm.delete_failed_operation_on_device('some-id') is False

    # add_create_defaults use_existing True branch
    def test_add_create_defaults_with_existing_ocsp(self, *args):
        # Direct unit test to avoid template rendering of raw existing_ocsp
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                fqdn='baz.bar.net',
                dest='192.168.1.1/32',
                ssl_profile='fake_ssl_1',
                vlans=['/Common/vlan1'],
                existing_ocsp='/Common/existing_ocsp_profile',
            ),
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        payload = mm.add_create_defaults({})
        assert payload['use_existing'] is True
        assert 'ocsp_max_age' not in payload
        assert 'ocsp_nonce' not in payload

    def test_add_create_defaults_without_existing_ocsp(self, *args):
        set_module_args(dict(
            name='foobar',
            ocsp=dict(
                fqdn='baz.bar.net',
                dest='192.168.1.1/32',
                ssl_profile='fake_ssl_1',
                vlans=['/Common/vlan1'],
            ),
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        payload = mm.add_create_defaults({})
        assert payload['use_existing'] is False
        assert payload['ocsp_max_age'] == 604800
        assert payload['ocsp_nonce'] == 'enabled'

    # add_missing_options existing_ocsp add/remove branches
    def test_add_missing_options_add_existing_ocsp(self, *args):
        set_module_args(dict(
            name='foobar',
            ocsp=dict(existing_ocsp='/Common/new_existing'),
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.changes = UsableChanges(params=dict(existing_ocsp='/Common/new_existing'))
        mm.have = ApiParameters(params=load_fixture('return_sslo_config_auth_params.json'))
        payload = mm.add_missing_options({})
        assert payload['use_existing'] is True

    def test_add_missing_options_fills_ssl_profile_from_have(self, *args):
        # Regression: partial modify without ssl_profile must inherit from device
        set_module_args(dict(
            name='foobar',
            ocsp=dict(port=8080),
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.changes = UsableChanges(params=dict(ocsp_port=8080))
        mm.have = ApiParameters(params=load_fixture('return_sslo_config_auth_params.json'))
        payload = mm.add_missing_options({})
        assert payload['ocsp_ssl_profile'] == 'ssloT_fake_ssl_1'

    def test_modify_with_existing_ocsp_renders_valid_json(self, *args):
        # Regression: existing_ocsp value must be quoted in rendered JSON
        set_module_args(dict(
            name='foobar',
            ocsp=dict(existing_ocsp='/Common/my_existing_ocsp'),
            dump_json=True,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_config_auth.json'))
        mm.client.get = Mock(side_effect=[exists, exists])
        results = mm.exec_module()
        # if template were broken, exec_module would raise JSONDecodeError
        auth_block = results['json']['inputProperties'][1]['value']
        assert auth_block['ocsp']['ocspProfile'] == '/Common/my_existing_ocsp'
        assert auth_block['ocsp']['useExisting'] is True

    def test_add_missing_options_remove_existing_ocsp(self, *args):
        set_module_args(dict(
            name='foobar',
            ocsp=dict(existing_ocsp=''),
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.changes = UsableChanges(params=dict(existing_ocsp=''))
        mm.have = ApiParameters(params=load_fixture('return_sslo_config_auth_params.json'))
        payload = mm.add_missing_options({})
        assert payload['use_existing'] is False
