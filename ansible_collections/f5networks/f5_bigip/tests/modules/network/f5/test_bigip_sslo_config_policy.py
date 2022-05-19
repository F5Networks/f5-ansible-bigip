# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_policy import (
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
            name="testpolicy",
            default_rule=dict(
                allow_block='block',
                tls_intercept='intercept',
                service_chain='foo_service'
            ),
            server_cert_check=True,
            proxy_connect=dict(
                username='testuser',
                password='',
                pool_members=[dict(ip='198.19.64.30', port=100)],
            ),
            policy_rules=[
                dict(
                    name='testrule',
                    match_type='match_any',
                    policy_action='reject',
                    conditions=[
                        dict(
                            condition_type='category_lookup_all',
                            condition_option_category=['Financial Data and Services', 'General Email']
                        ),
                        dict(
                            condition_type='client_port_match',
                            condition_option_ports=['80', '90']
                        ),
                        dict(
                            condition_type='client_ip_geolocation',
                            geolocations=[dict(type='countryCode', value='US'), dict(type='countryCode', value='UK')]
                        )
                    ]
                ),
                dict(
                    name='testrule2',
                    match_type='match_all',
                    policy_action='reject',
                    conditions=[
                        dict(
                            condition_type='category_lookup_all',
                            condition_option_category=['Financial Data and Services', 'General Email']
                        )
                    ]
                ),
            ]
        )

        p = ModuleParameters(params=args)
        assert p.policy_rules == [{'name': 'testrule', 'operation': 'OR', 'mode': 'edit', 'action': 'reject',
                                   'actionOptions': {'ssl': '', 'serviceChain': ''},
                                   'conditions': [{'type': 'Category Lookup',
                                                   'options': {
                                                       'category': ['Financial Data and Services', 'General Email']}},
                                                  {'type': 'Client Port Match', 'options': {'port': ['80', '90']}},
                                                  {'type': 'Client IP Geolocation',
                                                   'options': {'geolocations': [
                                                       {'matchType': 'countryCode',
                                                        'value': 'US'},
                                                       {'matchType': 'countryCode',
                                                        'value': 'UK'}]}}]},
                                  {'name': 'testrule2', 'operation': 'AND', 'mode': 'edit', 'action': 'reject',
                                   'actionOptions': {'ssl': '', 'serviceChain': ''},
                                   'conditions': [{'type': 'Category Lookup',
                                                   'options': {'category': ['Financial Data and Services', 'General '
                                                                                                           'Email']}}]},
                                  {'name': 'All Traffic', 'action': 'block', 'mode': 'edit',
                                   'actionOptions': {'ssl': 'intercept', 'serviceChain': 'ssloSC_foo_service'},
                                   'isDefault': True}
                                  ]
        assert p.default_rule_allow_block == 'block'
        assert p.default_rule_service_chain == 'ssloSC_foo_service'
        assert p.default_rule_tls_intercept == 'intercept'
        assert p.proxy_connect == {'isProxyChainEnabled': True, 'username': 'testuser', 'password': '',
                                   'pool': {'create': True, 'members': [{'ip': '198.19.64.30', 'port': '100'}],
                                            'name': '/Common/ssloP_testpolicy.app/ssloP_testpolicy_proxyChainPool'}}
        assert p.server_cert_check is True
        assert p.pools == {
            'ssloP_testpolicy_proxyChainPool': {'name': 'ssloP_testpolicy_proxyChainPool',
                                                'loadBalancingMode': 'predictive-node',
                                                'monitors': {'names': ['/Common/gateway_icmp']},
                                                'unhandledPool': True,
                                                'callerContext': 'policyConfigProcessor',
                                                'minActiveMembers': '0',
                                                'members': [{
                                                    'appService': 'ssloP_testpolicy.app/ssloP_testpolicy',
                                                    'ip': '198.19.64.30',
                                                    'port': '100',
                                                    'subPath': 'ssloP_testpolicy.app'}]
                                                }}

        assert p.name == 'ssloP_testpolicy'

    def test_api_parameters(self):
        args = load_fixture('return_sslo_policy_params.json')
        p = ApiParameters(params=args)

        assert p.policy_consumer == 'Outbound'
        assert p.policy_rules == [
            {
                "action": "reject",
                "actionOptions": {
                    "serviceChain": "",
                    "ssl": ""
                },
                "conditions": [
                    {
                        "options": {
                            "category": [
                                "Financial Data and Services",
                                "General Email"
                            ]
                        },
                        "type": "Category Lookup"
                    },
                    {
                        "options": {
                            "port": [
                                "80",
                                "90"
                            ]
                        },
                        "type": "Client Port Match"
                    },
                    {
                        "options": {
                            "geolocations": [
                                {
                                    "matchType": "countryCode",
                                    "value": "US"
                                },
                                {
                                    "matchType": "countryCode",
                                    "value": "UK"
                                }
                            ]
                        },
                        "type": "Client IP Geolocation"
                    }
                ],
                "mode": "edit",
                "name": "testrule",
                "operation": "OR",
                "phase": 2.0,
                "injectServerCertMacro": True,
                "injectCategorizationMacro": True
            },
            {
                "action": "reject",
                "actionOptions": {
                    "serviceChain": "",
                    "ssl": ""
                },
                "conditions": [
                    {
                        "options": {
                            "category": [
                                "Financial Data and Services",
                                "General Email"
                            ]
                        },
                        "type": "Category Lookup"
                    },
                    {
                        "options": {
                            "port": [
                                "80",
                                "90"
                            ]
                        },
                        "type": "Client Port Match"
                    }
                ],
                "mode": "edit",
                "name": "testrule2",
                "operation": "AND",
                "phase": 2.0
            },
            {
                "action": "allow",
                "actionOptions": {
                    "serviceChain": "",
                    "ssl": ""
                },
                "isDefault": True,
                "mode": "edit",
                "name": "All Traffic",
                "phase": 2.0
            }
        ]
        assert p.proxy_connect == {
            "isProxyChainEnabled": True,
            "password": "",
            "pool": {
                "create": True,
                "members": [
                    {
                        "ip": "192.168.30.10",
                        "port": "100"
                    }
                ],
                "name": "/Common/ssloP_testpolicy.app/ssloP_testpolicy_proxyChainPool"
            },
            "username": "testuser"
        }
        assert p.server_cert_check
        assert p.pools == {
            "ssloP_testpolicy_proxyChainPool": {
                "name": "ssloP_testpolicy_proxyChainPool",
                "loadBalancingMode": "predictive-node",
                "monitors": {
                    "names": [
                        "/Common/gateway_icmp"
                    ]
                },
                "members": [
                    {
                        "ip": "192.168.30.10",
                        "port": "100",
                        "appService": "ssloP_testpolicy.app/ssloP_testpolicy",
                        "subPath": "ssloP_testpolicy.app"
                    }
                ],
                "unhandledPool": True,
                "minActiveMembers": "0",
                "callerContext": "policyConfigProcessor"
            }
        }


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_policy.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_policy.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '8.0'

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_create_policy_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name="testpolicy",
            server_cert_check=True,
            proxy_connect=dict(
                username='testuser',
                password='',
                pool_members=[dict(ip='198.19.64.30', port=100)],
            ),
            policy_rules=[
                dict(
                    name='testrule',
                    match_type='match_any',
                    policy_action='reject',
                    conditions=[
                        dict(
                            condition_type='category_lookup_all',
                            condition_option_category=['Financial Data and Services', 'General Email']
                        ),
                        dict(
                            condition_type='client_port_match',
                            condition_option_ports=['80', '90']
                        ),
                        dict(
                            condition_type='client_ip_geolocation',
                            geolocations=[dict(type='countryCode', value='US'), dict(type='countryCode', value='UK')]
                        )
                    ]
                ),
                dict(
                    name='testrule2',
                    match_type='match_all',
                    policy_action='reject',
                    conditions=[
                        dict(
                            condition_type='category_lookup_all',
                            condition_option_category=['Financial Data and Services', 'General Email']
                        )
                    ]
                ),
            ]
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_policy_create_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_policy_create_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['pools'] == {'ssloP_testpolicy_proxyChainPool': {
            'name': 'ssloP_testpolicy_proxyChainPool',
            'loadBalancingMode': 'predictive-node',
            'monitors': {'names': ['/Common/gateway_icmp']},
            'minActiveMembers': '0',
            'unhandledPool': True,
            'callerContext': 'policyConfigProcessor',
            'members': [{'appService': 'ssloP_testpolicy.app/ssloP_testpolicy',
                         'ip': '198.19.64.30',
                         'port': '100',
                         'subPath': 'ssloP_testpolicy.app'
                         }]
        }}

        assert results['proxy_connect'] == {'isProxyChainEnabled': True, 'username': 'testuser', 'password': '',
                                            'pool': {'create': True, 'members': [{'ip': '198.19.64.30', 'port': '100'}],
                                                     'name': '/Common/ssloP_testpolicy.app'
                                                             '/ssloP_testpolicy_proxyChainPool'}}
        assert results['policy_rules'] == [{'name': 'testrule', 'operation': 'OR', 'mode': 'edit', 'action': 'reject',
                                            'actionOptions': {'ssl': '', 'serviceChain': ''},
                                            'conditions': [{'type': 'Category Lookup',
                                                            'options': {'category': ['Financial Data and Services',
                                                                                     'General Email']}},
                                                           {'type': 'Client Port Match',
                                                            'options': {'port': ['80', '90']}},
                                                           {'type': 'Client IP Geolocation',
                                                            'options': {'geolocations': [
                                                                {'matchType': 'countryCode',
                                                                 'value': 'US'},
                                                                {'matchType': 'countryCode',
                                                                 'value': 'UK'}]}}]},
                                           {'name': 'testrule2', 'operation': 'AND', 'mode': 'edit', 'action': 'reject',
                                            'actionOptions': {'ssl': '', 'serviceChain': ''},
                                            'conditions': [{'type': 'Category Lookup',
                                                            'options': {'category': ['Financial Data and Services',
                                                                                     'General Email']}}]},
                                           {'name': 'All Traffic', 'action': 'allow', 'mode': 'edit',
                                            'actionOptions': {'ssl': 'bypass', 'serviceChain': ''}, 'isDefault': True}]
