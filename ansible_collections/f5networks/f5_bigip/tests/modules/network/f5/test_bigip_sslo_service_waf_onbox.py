# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_waf_onbox import (
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
            name='waf1',
            waf_policy='/Common/Testing',
            dos_protection_profile='/Common/Test',
            bot_defense_profile='/Common/bot-defense',
            log_profiles=['/Common/local-dos', '/Common/Log all requests'],
            rules=['/Common/Test1', '/Common/Test2'],
        )
        p = ModuleParameters(params=args)
        assert p.name == 'ssloS_waf1'
        assert p.waf_policy == '/Common/Testing'
        assert p.dos_protection_profile == '/Common/Test'
        assert p.bot_defense_profile == '/Common/bot-defense'
        assert p.log_profiles == [
            {'name': '/Common/local-dos', 'value': '/Common/local-dos'},
            {'name': '/Common/Log all requests', 'value': '/Common/Log all requests'},
        ]
        assert p.rules == [
            {'name': '/Common/Test1', 'value': '/Common/Test1'},
            {'name': '/Common/Test2', 'value': '/Common/Test2'},
        ]

    def test_module_parameters_name_prefix(self):
        p = ModuleParameters(params=dict(name='ssloS_waf1'))
        assert p.name == 'ssloS_waf1'

    def test_module_parameters_none_lists(self):
        p = ModuleParameters(params=dict(name='waf1'))
        assert p.log_profiles is None
        assert p.rules is None

    def test_api_parameters(self):
        args = load_fixture('load_sslo_service_waf_onbox.json')
        p = ApiParameters(params=args['items'][0]['inputProperties'][1]['value'][0])
        assert p.waf_policy == '/Common/Testing'
        assert p.dos_protection_profile == '/Common/Test'
        assert p.bot_defense_profile == '/Common/bot-defense'
        assert p.log_profiles == [{'name': '/Common/local-dos', 'value': '/Common/local-dos'}]
        assert p.rules == [{'name': '/Common/Test1', 'value': '/Common/Test1'}]


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch(
            'ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_waf_onbox.F5Client'
        )
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch(
            'ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_waf_onbox.sslo_version'
        )
        self.m3 = self.p3.start()
        self.m3.return_value = '14.0'

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_create_waf_onbox_service_dump_json(self, *args):
        expected = load_fixture('sslo_waf_onbox_create_generated.json')
        set_module_args(dict(
            name='waf1',
            waf_policy='/Common/Testing',
            dos_protection_profile='/Common/Test',
            bot_defense_profile='/Common/bot-defense',
            log_profiles=['/Common/local-dos', '/Common/Log all requests'],
            rules=['/Common/Test1', '/Common/Test2'],
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

    def test_create_waf_onbox_service(self, *args):
        set_module_args(dict(
            name='waf1',
            waf_policy='/Common/Testing',
            dos_protection_profile='/Common/Test',
            bot_defense_profile='/Common/bot-defense',
            log_profiles=['/Common/local-dos'],
            rules=['/Common/Test1'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_waf_onbox_create_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_waf_onbox_create_done.json'))
        )

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['waf_policy'] == '/Common/Testing'
        assert results['log_profiles'] == ['/Common/local-dos']
        assert results['rules'] == ['/Common/Test1']

    def test_create_waf_onbox_missing_waf_policy_raises(self, *args):
        set_module_args(dict(name='waf1'))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError
        with self.assertRaises(F5ModuleError) as cm:
            mm.exec_module()
        assert 'waf_policy' in str(cm.exception)

    def test_create_waf_onbox_defaults(self, *args):
        set_module_args(dict(
            name='waf1',
            waf_policy='/Common/Testing',
            dump_json=True,
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
        svc = payload['inputProperties'][1]['value'][0]['customService']
        assert svc['serviceDownAction'] == 'reset'
        assert svc['serviceSpecific']['iRuleList'] == []
        assert svc['serviceSpecific']['logProfile'] == []

    def test_modify_waf_onbox_service(self, *args):
        set_module_args(dict(
            name='waf1',
            waf_policy='/Common/UpdatedPolicy',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_waf_onbox.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_waf_onbox_modify_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_waf_onbox_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['waf_policy'] == '/Common/UpdatedPolicy'

    def test_modify_waf_onbox_service_idempotent(self, *args):
        set_module_args(dict(
            name='waf1',
            waf_policy='/Common/Testing',
            dos_protection_profile='/Common/Test',
            bot_defense_profile='/Common/bot-defense',
            log_profiles=['/Common/local-dos'],
            rules=['/Common/Test1'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_waf_onbox.json'))
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()
        assert results['changed'] is False

    def test_modify_waf_onbox_service_idempotent_partial(self, *args):
        # Only waf_policy supplied; it matches the existing value - no change expected
        set_module_args(dict(
            name='waf1',
            waf_policy='/Common/Testing',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_waf_onbox.json'))
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()
        assert results['changed'] is False

    def test_delete_waf_onbox_service(self, *args):
        set_module_args(dict(name='waf1', state='absent'))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_waf_onbox.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_waf_onbox_delete_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_waf_onbox_delete_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True

    def test_version_check_raises_below_min(self, *args):
        self.m3.return_value = '10.0'
        set_module_args(dict(name='waf1', waf_policy='/Common/Testing'))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError
        with self.assertRaises(F5ModuleError) as cm:
            mm.exec_module()
        assert '11.0' in str(cm.exception)

    def test_service_type_in_payload(self, *args):
        set_module_args(dict(
            name='waf1',
            waf_policy='/Common/Testing',
            dump_json=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()
        payload = results['json']
        svc = payload['inputProperties'][1]['value'][0]['customService']
        assert svc['serviceType'] == 'awaf'
        assert payload['inputProperties'][1]['value'][0]['vendorInfo']['name'] == 'F5 Advanced WAF (On-Box)'
        assert payload['inputProperties'][1]['value'][0]['description'] == 'Type: awaf'
        assert payload['inputProperties'][1]['value'][0]['strictness'] is True


if __name__ == '__main__':
    unittest.main()
