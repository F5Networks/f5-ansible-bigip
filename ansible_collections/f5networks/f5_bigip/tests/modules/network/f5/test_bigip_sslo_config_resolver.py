# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_resolver import (
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
            fwd_zones=[
                dict(
                    zone='foobar',
                    servers=['192.168.1.1', '192.168.1.2']
                ),
                dict(
                    zone='.',
                    servers=['fd66:2735:1533:46c1:68c8:0:0:7113', '8.8.8.8', '8.8.4.4']
                )
            ]
        )
        p = ModuleParameters(params=args)

        assert p.ip_family == 'both'
        assert p.fwd_zones == [
            {'zone': 'foobar', 'nameServerIps': ['192.168.1.1', '192.168.1.2']},
            {'zone': '.', 'nameServerIps': ['fd66:2735:1533:46c1:68c8:0:0:7113', '8.8.8.8', '8.8.4.4']}
        ]

    def test_api_parameters(self):
        args = load_fixture('return_sslo_resolver_params.json')
        p = ApiParameters(params=args)

        assert p.ip_family == 'both'
        assert p.fwd_name_servers == [
            '10.1.20.1', '10.1.20.2', 'fd66:2735:1533:46c1:68c8:0:0:7110', 'fd66:2735:1533:46c1:68c8:0:0:7111'
        ]

    def test_ipv4_family_zone(self):
        args = dict(
            fwd_zones=[
                dict(
                    zone='foobar',
                    servers=['192.168.1.1', '192.168.1.2']
                ),
                dict(
                    zone='.',
                    servers=['8.8.8.8', '8.8.4.4']
                )
            ]
        )
        p = ModuleParameters(params=args)

        assert p.ip_family == 'ipv4'
        assert p.fwd_zones == [
            {'zone': 'foobar', 'nameServerIps': ['192.168.1.1', '192.168.1.2']},
            {'zone': '.', 'nameServerIps': ['8.8.8.8', '8.8.4.4']}
        ]

    def test_ipv6_family_zone(self):
        args = dict(
            fwd_zones=[
                dict(
                    zone='foobar',
                    servers=['fd66:2735:1533:46c1:68c8:0:0:7110']
                ),
                dict(
                    zone='.',
                    servers=['fd66:2735:1533:46c1:68c8:0:0:7111']
                )
            ]
        )
        p = ModuleParameters(params=args)

        assert p.ip_family == 'ipv6'
        assert p.fwd_zones == [
            {'zone': 'foobar', 'nameServerIps': ['fd66:2735:1533:46c1:68c8:0:0:7110']},
            {'zone': '.', 'nameServerIps': ['fd66:2735:1533:46c1:68c8:0:0:7111']}
        ]

    def test_ipv4_family_name(self):
        args = dict(
            fwd_name_servers=['10.1.20.1', '10.1.20.2']
        )
        p = ModuleParameters(params=args)

        assert p.ip_family == 'ipv4'
        assert p.fwd_name_servers == ['10.1.20.1', '10.1.20.2']

    def test_ipv6_family_name(self):
        args = dict(
            fwd_name_servers=['fd66:2735:1533:46c1:68c8:0:0:7110', 'fd66:2735:1533:46c1:68c8:0:0:7111']
        )
        p = ModuleParameters(params=args)

        assert p.ip_family == 'ipv6'
        assert p.fwd_name_servers == ['fd66:2735:1533:46c1:68c8:0:0:7110', 'fd66:2735:1533:46c1:68c8:0:0:7111']

    def test_invalid_zone_server(self):
        args = dict(
            fwd_zones=[
                dict(
                    zone='foobar',
                    servers=['99.278.88.88']
                )
            ]
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.fwd_zones is None
        assert str(res.exception) == 'A submitted IP address: 99.278.88.88 is not a valid IP address.'

    def test_invalid_name_server(self):
        args = dict(
            fwd_name_servers=['99.278.88.88']
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.fwd_name_servers is None
        assert str(res.exception) == 'A submitted IP address: 99.278.88.88 is not a valid IP address.'

    def test_empty_zone_name(self):
        args = dict(
            fwd_zones=[
                dict(
                    zone=None,
                    servers=['99.245.88.88']
                )
            ]
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.fwd_zones is None
        assert str(res.exception) == "A forwarding zone 'zone' key must contain a valid domain name entry."

    def test_empty_zone_server(self):
        args = dict(
            fwd_zones=[
                dict(
                    zone='foobar',
                    servers=None
                )
            ]
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            assert p.fwd_zones is None
        assert str(res.exception) == "A forwarding zone 'servers' key must contain at least one IP address entry."


class TestManagerSSLO(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch(
            'ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_resolver.F5Client'
        )
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch(
            'ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_resolver.sslo_version'
        )
        self.m3 = self.p3.start()
        self.m3.return_value = '9.0'

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_create_resolver_object_fwd_zones_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_resolver_create_fwd_zones_generated.json')
        set_module_args(dict(
            fwd_zones=[
                dict(
                    zone='foobar',
                    servers=['192.168.1.1', '192.168.1.2']
                ),
                dict(
                    zone='.',
                    servers=['fd66:2735:1533:46c1:68c8:0:0:7113', '8.8.8.8', '8.8.4.4']
                )
            ],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_resolver_object_fwd_name_servers_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_resolver_create_fwd_name_servers_generated.json')
        set_module_args(dict(
            fwd_name_servers=[
                '10.1.20.1',
                '10.1.20.2',
                'fd66:2735:1533:46c1:68c8:0:0:7110',
                'fd66:2735:1533:46c1:68c8:0:0:7111'
            ],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_modify_resolver_object_fwd_zones_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_resolver_modify_fwd_zones_generated.json')
        set_module_args(dict(
            fwd_zones=[
                dict(
                    zone='foobar',
                    servers=['192.168.1.1', '192.168.1.2']
                ),
                dict(
                    zone='.',
                    servers=['fd66:2735:1533:46c1:68c8:0:0:7113', '8.8.8.8', '8.8.4.4']
                )
            ],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_resolver_zones.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_modify_resolver_object_fwd_name_servers_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_resolver_modify_fwd_name_servers_generated.json')
        set_module_args(dict(
            fwd_name_servers=[
                '10.1.20.1',
                '10.1.20.2',
                'fd66:2735:1533:46c1:68c8:0:0:7110',
                'fd66:2735:1533:46c1:68c8:0:0:7111'
            ],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_resolver_fwd_server.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_resolver_object_fwd_zones(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = [{'zone': 'foobar', 'nameServerIps': ['192.168.1.1', '192.168.1.2']},
                    {'zone': '.', 'nameServerIps': ['fd66:2735:1533:46c1:68c8:0:0:7113', '8.8.8.8', '8.8.4.4']}]
        set_module_args(dict(
            fwd_zones=[
                dict(
                    zone='foobar',
                    servers=['192.168.1.1', '192.168.1.2']
                ),
                dict(
                    zone='.',
                    servers=['fd66:2735:1533:46c1:68c8:0:0:7113', '8.8.8.8', '8.8.4.4']
                )
            ],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)
        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_resolver_create_fwd_zones_start.json')
        ))
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_resolver_create_fwd_zones_done.json')
        ))

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['fwd_zones'] == expected
        assert results['ip_family'] == 'both'
        assert mm.client.get.call_count == 1
        assert mm.client.post.call_count == 1

    def test_create_resolver_object_fwd_name_servers(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = ['10.1.20.1', '10.1.20.2', 'fd66:2735:1533:46c1:68c8:0:0:7110', 'fd66:2735:1533:46c1:68c8:0:0:7111']
        set_module_args(dict(
            fwd_name_servers=[
                '10.1.20.1',
                '10.1.20.2',
                'fd66:2735:1533:46c1:68c8:0:0:7110',
                'fd66:2735:1533:46c1:68c8:0:0:7111'
            ],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_resolver_create_fwd_servers_start.json')
        ))
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_resolver_create_fwd_servers_done.json')
        ))

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['fwd_name_servers'] == expected
        assert results['ip_family'] == 'both'
        assert mm.client.get.call_count == 1
        assert mm.client.post.call_count == 1

    def test_modify_resolver_object_fwd_zones(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = [{'zone': 'foobar', 'nameServerIps': ['192.168.1.1', '192.168.1.2']},
                    {'zone': '.', 'nameServerIps': ['fd66:2735:1533:46c1:68c8:0:0:7113', '8.8.8.8', '8.8.4.4']}]
        set_module_args(dict(
            fwd_zones=[
                dict(
                    zone='foobar',
                    servers=['192.168.1.1', '192.168.1.2']
                ),
                dict(
                    zone='.',
                    servers=['fd66:2735:1533:46c1:68c8:0:0:7113', '8.8.8.8', '8.8.4.4']
                )
            ],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        exists = dict(code=200, contents=load_fixture('load_sslo_resolver_zones.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_resolver_modify_fwd_zones_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_resolver_modify_fwd_zones_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['fwd_zones'] == expected
        assert mm.client.get.call_count == 3
        assert mm.client.post.call_count == 1

    def test_modify_resolver_object_fwd_name_servers(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = ['10.1.20.1', '10.1.20.2', 'fd66:2735:1533:46c1:68c8:0:0:7110', 'fd66:2735:1533:46c1:68c8:0:0:7111']
        set_module_args(dict(
            fwd_name_servers=[
                '10.1.20.1',
                '10.1.20.2',
                'fd66:2735:1533:46c1:68c8:0:0:7110',
                'fd66:2735:1533:46c1:68c8:0:0:7111'
            ],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_resolver_fwd_server.json'))
        # Override methods to force specific logic in the module to happen
        done = dict(code=200, contents=load_fixture('reply_sslo_resolver_modify_fwd_servers_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_resolver_modify_fwd_servers_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['fwd_name_servers'] == expected
        assert mm.client.get.call_count == 3
        assert mm.client.post.call_count == 1
