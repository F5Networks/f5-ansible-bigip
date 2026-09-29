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
from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_sslo_config_policy
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
    def setUp(self):
        self.p1 = patch('time.time')
        self.p1.start()
        self.p1.return_value = 0

    def tearDown(self):
        self.p1.stop()

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
        assert p.policy_rules == [{'index': 1, 'name': 'testrule', 'operation': 'OR', 'mode': 'edit', 'action': 'reject',
                                   'actionOptions': {'ssl': '', 'serviceChain': '', 'urlRedirect': ''},
                                   'conditions': [{'index': 11, 'type': 'Category Lookup',
                                                   'options': {'category': ['Financial Data and Services', 'General '
                                                                                                           'Email']}},
                                                  {'index': 21, 'type': 'Client Port Match', 'options': {'port': ['80', '90']}},
                                                  {'index': 31, 'type': 'Client IP Geolocation',
                                                   'options': {'geolocations': [
                                                       {'matchType': 'countryCode',
                                                        'value': 'US',
                                                        'valueType': 'staticValue'},
                                                       {'matchType': 'countryCode',
                                                        'value': 'UK',
                                                        'valueType': 'staticValue'}]}}]},
                                  {'index': 41, 'name': 'testrule2', 'operation': 'AND', 'mode': 'edit', 'action': 'reject',
                                   'actionOptions': {'ssl': '', 'serviceChain': '', 'urlRedirect': ''},
                                   'conditions': [{'index': 51, 'type': 'Category Lookup',
                                                   'options': {
                                                       'category': ['Financial Data and Services', 'General Email']}}]},
                                  {'name': 'All Traffic', 'action': 'block', 'mode': 'edit', 'actionOptions': {'ssl': 'intercept',
                                                                                                               'serviceChain': 'ssloSC_foo_service'},
                                   'isDefault': True}]
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

    def test_new_condition_types(self):
        """Test new condition types: ip_reputation, client_vlan, ip_protocol, cert, server_name, url_match."""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_reputation',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='client_ip_reputation',
                            condition_option_ip_reputation='bad'
                        )
                    ]
                ),
                dict(
                    name='rule_reputation_category',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='server_ip_reputation',
                            condition_option_ip_reputation='category',
                            condition_option_ip_reputation_category=['BotNets', 'Phishing']
                        )
                    ]
                ),
                dict(
                    name='rule_vlan',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='client_vlan',
                            condition_option_vlan=['/Common/internal', '/Common/external']
                        )
                    ]
                ),
                dict(
                    name='rule_ip_protocol',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='ip_protocol',
                            condition_option_ip_protocol='tcp'
                        )
                    ]
                ),
                dict(
                    name='rule_cert',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='server_cert_subject_dn',
                            condition_option_cert=[
                                dict(type='f5keyequalf5', value='CN=example.com'),
                                dict(type='f5keysubstringf5', value='example')
                            ]
                        )
                    ]
                ),
                dict(
                    name='rule_server_name',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='server_name_tls_clienthello',
                            condition_option_server_name=[
                                dict(type='f5keyprefixf5', value='api.')
                            ]
                        )
                    ]
                ),
                dict(
                    name='rule_url_match',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='url_match',
                            condition_option_url=[
                                dict(type='f5keyequalf5', value='http://example.com/path')
                            ]
                        )
                    ]
                ),
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules

        # reputation: bad  (rule0 index=1, cond index=11)
        assert rules[0]['conditions'][0] == {
            'index': 11, 'type': 'Client IP Reputation',
            'options': {'reputation': 'bad', 'category': []}
        }
        # reputation: category  (rule1 index=21, cond index=31)
        assert rules[1]['conditions'][0] == {
            'index': 31, 'type': 'Server IP Reputation',
            'options': {'reputation': 'category', 'category': ['BotNets', 'Phishing']}
        }
        # client_vlan  (rule2 index=41, cond index=51)
        assert rules[2]['conditions'][0] == {
            'index': 51, 'type': 'Client VLANs',
            'options': {'vlans': ['/Common/internal', '/Common/external']}
        }
        # ip_protocol  (rule3 index=61, cond index=71)
        assert rules[3]['conditions'][0] == {
            'index': 71, 'type': 'IP Protocol',
            'options': {'ipProtocol': 'tcp'}
        }
        # cert subject dn - staticValue  (rule4 index=81, cond index=91)
        assert rules[4]['conditions'][0] == {
            'index': 91, 'type': 'Server Certificate (Subject DN)',
            'options': {'value': [
                {'matchType': 'f5keyequalf5', 'pattern': 'CN=example.com', 'valueType': 'staticValue'},
                {'matchType': 'f5keysubstringf5', 'pattern': 'example', 'valueType': 'staticValue'}
            ]}
        }
        # server_name_tls_clienthello  (rule5 index=101, cond index=111)
        assert rules[5]['conditions'][0] == {
            'index': 111, 'type': 'Server Name (TLS ClientHello)',
            'options': {'value': [
                {'matchType': 'f5keyprefixf5', 'pattern': 'api.', 'valueType': 'staticValue'}
            ]}
        }
        # url_match  (rule6 index=121, cond index=131)
        assert rules[6]['conditions'][0] == {
            'index': 131, 'type': 'URL Branching',
            'options': {'url': [
                {'matchType': 'f5keyequalf5', 'pattern': 'http://example.com/path'}
            ]}
        }

    def test_cert_condition_datagroup_reference(self):
        """Test that cert condition with datagroup path uses valueType=datagroup."""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_cert_dg',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='server_cert_subject_dn',
                            condition_option_cert=[
                                dict(type='f5keyequalf5', value='/Common/my_dg')
                            ]
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        assert rules[0]['conditions'][0]['options']['value'][0]['valueType'] == 'datagroup'

    def test_redirect_action(self):
        """Test redirect policy action sets actionOptions correctly."""
        args = dict(
            name="testpolicy",
            sslo_version='11.1',
            policy_rules=[
                dict(
                    name='rule_redirect',
                    match_type='match_any',
                    policy_action='redirect',
                    redirect_url='https://block.example.com/blocked',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='category_lookup_all',
                            condition_option_category=['General Email']
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        assert rules[0]['action'] == 'redirect'
        assert rules[0]['actionOptions']['ssl'] == 'intercept'
        assert rules[0]['actionOptions']['urlRedirect'] == 'https://block.example.com/blocked'

    def test_redirect_action_version_check(self):
        """Test redirect action raises error on SSLO < 11.1."""
        args = dict(
            name="testpolicy",
            sslo_version='8.0',
            policy_rules=[
                dict(
                    name='rule_redirect',
                    match_type='match_any',
                    policy_action='redirect',
                    redirect_url='https://block.example.com/blocked',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert '11.1' in msg
        assert 'Detected version' in msg
        assert '8.0' in msg

    def test_redirect_action_invalid_url(self):
        """Test redirect action raises error when URL does not start with http(s)://."""
        args = dict(
            name="testpolicy",
            sslo_version='11.1',
            policy_rules=[
                dict(
                    name='rule_redirect',
                    match_type='match_any',
                    policy_action='redirect',
                    redirect_url='ftp://invalid.example.com',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert 'http://' in str(err.exception)

    def test_ip_reputation_invalid_value(self):
        """Test ip_reputation raises error for invalid option."""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_rep',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='client_ip_reputation',
                            condition_option_ip_reputation='unknown'
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert 'condition_option_ip_reputation' in str(err.exception)

    def test_ip_reputation_category_missing(self):
        """Test ip_reputation=category raises error when category list not provided."""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_rep',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='client_ip_reputation',
                            condition_option_ip_reputation='category'
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert 'condition_option_ip_reputation_category' in str(err.exception)

    def test_ip_reputation_category_invalid_value(self):
        args = dict(
            name='testpolicy',
            policy_rules=[
                dict(
                    name='rule_rep', match_type='match_any', policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='client_ip_reputation',
                        condition_option_ip_reputation='category',
                        condition_option_ip_reputation_category=['invalid category']
                    )]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaisesRegex(F5ModuleError, 'invalid category'):
            p.policy_rules

    def test_cert_condition_invalid_match_type(self):
        """Test cert condition raises error for invalid match type."""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_cert',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='server_cert_subject_dn',
                            condition_option_cert=[
                                dict(type='invalid_type', value='CN=example.com')
                            ]
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert "'server_cert' match type" in msg
        assert 'invalid_type' in msg

    def test_cert_condition_datagroup_glob_raises(self):
        """Test cert condition raises error when using f5keyglobalf5 with a datagroup path."""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_cert',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='server_cert_subject_dn',
                            condition_option_cert=[
                                dict(type='f5keyglobalf5', value='/Common/my_dg')
                            ]
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert 'f5keyglobalf5' in str(err.exception)

    def test_ip_protocol_invalid_value(self):
        """Test ip_protocol raises error for invalid protocol value."""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_proto',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='ip_protocol',
                            condition_option_ip_protocol='icmp'
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert 'ip_protocol' in str(err.exception)

    def test_url_match_invalid_match_type(self):
        """url_match shares _build_match_pattern_list with cert/server_name, so an invalid
        match type must raise an error labeled 'url_match'."""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_url',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='url_match',
                            condition_option_url=[
                                dict(type='bogus_type', value='http://example.com')
                            ]
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert "'url_match' match type" in msg
        assert 'bogus_type' in msg

    def test_url_match_path_not_treated_as_datagroup(self):
        """url_match passes check_datagroup=False to _build_match_pattern_list, so a value
        that looks like a datagroup path (/Common/foo) must NOT be tagged as 'datagroup'
        and must NOT receive a valueType key at all."""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_url',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='url_match',
                            condition_option_url=[
                                dict(type='f5keyequalf5', value='/Common/looks_like_dg')
                            ]
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        url_entry = rules[0]['conditions'][0]['options']['url'][0]
        assert url_entry == {
            'matchType': 'f5keyequalf5',
            'pattern': '/Common/looks_like_dg'
        }
        assert 'valueType' not in url_entry

    def test_url_match_allow_without_ssl_or_service_chain(self):
        """Bugzilla 2502149: 'allow' + 'url_match' should not require 'ssl_action' or 'service_chain'
        """
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_url_allow',
                    match_type='match_any',
                    policy_action='allow',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='url_match',
                            condition_option_url=[
                                dict(type='f5keyequalf5', value='/allowed')
                            ]
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        assert rules[0]['actionOptions'] == {'ssl': '', 'serviceChain': '', 'urlRedirect': ''}

    def test_url_match_allow_with_ssl_action_raises(self):
        """Bugzilla 2502149: 'ssl_action' must be rejected for 'allow' +
        'url_match' condition"""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_url_allow',
                    match_type='match_any',
                    policy_action='allow',
                    ssl_action='bypass',
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='url_match',
                            condition_option_url=[
                                dict(type='f5keyequalf5', value='/allowed')
                            ]
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert "url_match" in msg
        assert "ssl_action" in msg

    def test_url_match_allow_with_service_chain_raises(self):
        """Bugzilla 2502149: 'service_chain' must be rejected for 'allow' +
        'url_match' condition"""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_url_allow',
                    match_type='match_any',
                    policy_action='allow',
                    ssl_action=None,
                    service_chain='sc1',
                    conditions=[
                        dict(
                            condition_type='url_match',
                            condition_option_url=[
                                dict(type='f5keyequalf5', value='/allowed')
                            ]
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert "url_match" in msg
        assert "service_chain" in msg

    def test_allow_other_phase_requires_ssl_action(self):
        """Outside the HTTP/L7 protocol phases, 'ssl_action' is mandatory for 'allow' rules."""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_allow',
                    match_type='match_any',
                    policy_action='allow',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='ip_protocol',
                            condition_option_ip_protocol='tcp'
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert "'ssl_action'" in msg
        assert "'allow'" in msg

    def test_allow_other_phase_service_chain_optional(self):
        """Outside the HTTP/L7 protocol phases, 'service_chain' remains optional for 'allow'
        rules as long as 'ssl_action' is provided."""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_allow',
                    match_type='match_any',
                    policy_action='allow',
                    ssl_action='bypass',
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='ip_protocol',
                            condition_option_ip_protocol='tcp'
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        assert rules[0]['actionOptions'] == {'ssl': 'bypass', 'serviceChain': '', 'urlRedirect': ''}

    def test_l7_lookup_allow_with_ssl_action_raises(self):
        """Bugzilla 2502149: 'allow' + 'tcp_l7_protocol_lookup' or
        'udp_l7_protocol_lookup' condition run in the L7 protocol phase, so 'ssl_action'
        must be rejected."""
        for condition_type, option_key, option_value, other_key in (
            ('tcp_l7_protocol_lookup', 'option_tcp_protocol', ['http'], 'option_udp_protocol'),
            ('udp_l7_protocol_lookup', 'option_udp_protocol', ['dns'], 'option_tcp_protocol'),
        ):
            args = dict(
                name="testpolicy",
                sslo_version='9.0',
                policy_rules=[
                    dict(
                        name='rule_l7_allow',
                        match_type='match_any',
                        policy_action='allow',
                        ssl_action='bypass',
                        service_chain='sc1',
                        conditions=[
                            dict(condition_type=condition_type, **{option_key: option_value, other_key: None})
                        ]
                    )
                ]
            )
            p = ModuleParameters(params=args)
            with self.assertRaises(F5ModuleError) as err:
                p.policy_rules
            msg = str(err.exception)
            assert condition_type in msg
            assert "ssl_action" in msg

    def test_l7_lookup_allow_without_ssl_action_or_service_chain_succeeds(self):
        """'allow' + 'tcp_l7_protocol_lookup'/'udp_l7_protocol_lookup' does not require or
        accept 'ssl_action', and 'service_chain' remains optional (not mandatory)."""
        args = dict(
            name="testpolicy",
            sslo_version='9.0',
            policy_rules=[
                dict(
                    name='rule_l7_no_sc',
                    match_type='match_any',
                    policy_action='allow',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='tcp_l7_protocol_lookup',
                            option_tcp_protocol=['http'],
                            option_udp_protocol=None
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        assert rules[0]['actionOptions'] == {
            'ssl': '', 'serviceChain': '', 'urlRedirect': ''
        }

    def test_l7_lookup_allow_with_service_chain_succeeds(self):
        """'allow' + 'tcp_l7_protocol_lookup' with only 'service_chain' set is valid, and
        'ssl' in actionOptions stays blank."""
        args = dict(
            name="testpolicy",
            sslo_version='9.0',
            policy_rules=[
                dict(
                    name='rule_l7_allow_ok',
                    match_type='match_any',
                    policy_action='allow',
                    ssl_action=None,
                    service_chain='chain1',
                    conditions=[
                        dict(
                            condition_type='tcp_l7_protocol_lookup',
                            option_tcp_protocol=['http'],
                            option_udp_protocol=None
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        assert rules[0]['actionOptions'] == {
            'ssl': '', 'serviceChain': 'ssloSC_chain1', 'urlRedirect': ''
        }

    def test_l7_lookup_reject_with_service_chain_raises(self):
        """Unlike 'allow', a 'reject'/'abort' rule with an L7-phase condition does not
        support 'service_chain' either."""
        args = dict(
            name="testpolicy",
            sslo_version='9.0',
            policy_rules=[
                dict(
                    name='rule_l7_reject',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain='sc1',
                    conditions=[
                        dict(
                            condition_type='tcp_l7_protocol_lookup',
                            option_tcp_protocol=['http'],
                            option_udp_protocol=None
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert "tcp_l7_protocol_lookup" in msg
        assert "service_chain" in msg

    def test_url_match_abort_with_ssl_action_raises(self):
        """An 'abort' rule with a 'url_match' (HTTP-phase) condition does not support
        'ssl_action' or 'service_chain'."""
        args = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_url_abort',
                    match_type='match_any',
                    policy_action='abort',
                    ssl_action='bypass',
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='url_match',
                            condition_option_url=[
                                dict(type='f5keyequalf5', value='/blocked')
                            ]
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert "url_match" in msg
        assert "ssl_action" in msg

    def test_redirect_http_phase_with_service_chain_raises(self):
        """A 'redirect' rule with a 'url_match' (HTTP-phase) condition forces ssl_action to
        'intercept' and does not support 'service_chain'."""
        args = dict(
            name="testpolicy",
            sslo_version='11.1',
            policy_rules=[
                dict(
                    name='rule_url_redirect',
                    match_type='match_any',
                    policy_action='redirect',
                    redirect_url='https://block.example.com',
                    ssl_action=None,
                    service_chain='sc1',
                    conditions=[
                        dict(
                            condition_type='url_match',
                            condition_option_url=[
                                dict(type='f5keyequalf5', value='/blocked')
                            ]
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert "url_match" in msg
        assert "service_chain" in msg

    def test_redirect_l7_phase_service_chain_optional(self):
        """A 'redirect' rule with a 'tcp_l7_protocol_lookup' (L7-phase) condition forces
        ssl_action to 'intercept' and still supports an optional 'service_chain'."""
        args = dict(
            name="testpolicy",
            sslo_version='11.1',
            policy_rules=[
                dict(
                    name='rule_l7_redirect',
                    match_type='match_any',
                    policy_action='redirect',
                    redirect_url='https://block.example.com',
                    ssl_action=None,
                    service_chain='chain1',
                    conditions=[
                        dict(
                            condition_type='tcp_l7_protocol_lookup',
                            option_tcp_protocol=['http'],
                            option_udp_protocol=None
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        assert rules[0]['actionOptions'] == {
            'ssl': 'intercept', 'serviceChain': 'ssloSC_chain1',
            'urlRedirect': 'https://block.example.com'
        }

    def test_cert_condition_missing_type_or_value(self):
        """_build_match_pattern_list must reject items that omit either 'type' or 'value'."""
        # Missing 'value'
        args_missing_value = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_cert',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='server_cert_subject_dn',
                            condition_option_cert=[dict(type='f5keyequalf5')]
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args_missing_value)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert "'type' and 'value'" in str(err.exception)

        # Missing 'type'
        args_missing_type = dict(
            name="testpolicy",
            policy_rules=[
                dict(
                    name='rule_cert',
                    match_type='match_any',
                    policy_action='reject',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='server_cert_subject_dn',
                            condition_option_cert=[dict(value='CN=example.com')]
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args_missing_type)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert "'type' and 'value'" in str(err.exception)

    def test_api_parameters(self):
        args = load_fixture('return_sslo_policy_params.json')
        p = ApiParameters(params=args)

        assert p.policy_consumer == 'Outbound'
        assert p.policy_rules == [{'action': 'reject', 'actionOptions': {'serviceChain': '', 'ssl': ''},
                                   'conditions': [
                                       {'options': {'category': ['Financial Data and Services', 'General Email']},
                                        'type': 'Category Lookup'},
                                       {'options': {'port': ['80', '90']},
                                        'type': 'Client Port Match'},
                                       {'options':
                                           {
                                               'geolocations': [
                                                   {'matchType': 'countryCode', 'value': 'US'},
                                                   {'matchType': 'countryCode', 'value': 'UK'}]},
                                           'type': 'Client IP Geolocation'}],
                                   'mode': 'edit', 'name': 'testrule', 'operation': 'OR'},
                                  {'action': 'reject', 'actionOptions': {'serviceChain': '', 'ssl': ''},
                                   'conditions': [{'options': {'category': ['Financial Data and Services',
                                                                            'General Email']},
                                                   'type': 'Category Lookup'}, {'options': {'port': ['80', '90']},
                                                                                'type': 'Client Port Match'}],
                                   'mode': 'edit', 'name': 'testrule2', 'operation': 'AND'},
                                  {'action': 'allow', 'actionOptions': {'serviceChain': '', 'ssl': ''},
                                   'isDefault': True, 'mode': 'edit', 'name': 'All Traffic'}]

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

    # policy_consumer / policy_provider matrix
    def test_policy_consumer_outbound_invalid_provider(self):
        """Outbound + non-prp provider must raise."""
        args = dict(name='testpolicy', policy_consumer='outbound', policy_provider='ltm')
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_provider
        msg = str(err.exception)
        assert "outbound" in msg
        assert "prp" in msg

    def test_policy_provider_outbound_defaults_to_prp(self):
        """Outbound without policy_provider must default to 'prp'."""
        args = dict(name='testpolicy', policy_consumer='outbound')
        p = ModuleParameters(params=args)
        assert p.policy_consumer == 'Outbound'
        assert p.policy_provider == 'prp'

    def test_policy_provider_inbound_defaults_to_prp(self):
        """Inbound without policy_provider must default to 'prp'."""
        args = dict(name='testpolicy', policy_consumer='inbound')
        p = ModuleParameters(params=args)
        assert p.policy_consumer == 'Inbound'
        assert p.policy_provider == 'prp'

    def test_inbound_ltm_invalid_action_raises(self):
        """Inbound + ltm only allows 'allow'/'abort'; 'reject' must raise."""
        args = dict(
            name='testpolicy',
            policy_consumer='inbound',
            policy_provider='ltm',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action='intercept', service_chain=None,
                    conditions=[]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert "'inbound'" in msg.lower() or "Inbound" in msg
        assert "ltm" in msg
        assert "reject" in msg

    def test_inbound_ltm_invalid_ssl_action_on_allow(self):
        """Inbound + ltm + allow only permits ssl_action=intercept (or None)."""
        args = dict(
            name='testpolicy',
            policy_consumer='inbound',
            policy_provider='ltm',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='allow',
                    ssl_action='bypass', service_chain=None,
                    conditions=[]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert "ssl_action" in msg
        assert "bypass" in msg
        assert "intercept" in msg

    def test_inbound_ltm_valid_combo(self):
        """Inbound + ltm + allow + intercept on an allowed condition works."""
        args = dict(
            name='testpolicy',
            policy_consumer='inbound',
            policy_provider='ltm',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='allow',
                    ssl_action='intercept',
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='ip_protocol',
                            condition_option_ip_protocol='tcp'
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        assert rules[0]['action'] == 'allow'
        assert rules[0]['actionOptions']['ssl'] == 'intercept'
        assert rules[0]['conditions'][0]['type'] == 'IP Protocol'

    def test_inbound_ltm_disallowed_condition_type(self):
        """Inbound + ltm does not allow category_lookup_all."""
        args = dict(
            name='testpolicy',
            policy_consumer='inbound',
            policy_provider='ltm',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='allow',
                    ssl_action='intercept',
                    service_chain=None,
                    conditions=[
                        dict(
                            condition_type='category_lookup_all',
                            condition_option_category=['General Email']
                        )
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert "category_lookup_all" in msg
        assert "not supported" in msg

    # Condition_type coverage
    def test_ssl_check_condition(self):
        """ssl_check produces {'options': {'ssl': True}} with correct type."""
        args = dict(
            name='testpolicy',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(condition_type='ssl_check')]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        assert rules[0]['conditions'][0]['type'] == 'SSL Check'
        assert rules[0]['conditions'][0]['options'] == {'ssl': True}

    def test_category_lookup_sni_and_httpconnect(self):
        """category_lookup_sni and category_lookup_httpconnect map to correct types."""
        args = dict(
            name='testpolicy',
            policy_rules=[
                dict(
                    name='rsni', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='category_lookup_sni',
                        condition_option_category=['General Email']
                    )]
                ),
                dict(
                    name='rhc', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='category_lookup_httpconnect',
                        condition_option_category=['General Email']
                    )]
                ),
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        assert rules[0]['conditions'][0]['type'] == 'SNI Category Lookup'
        assert rules[1]['conditions'][0]['type'] == 'HTTP Connect Category Lookup'

    def test_category_invalid_value_raises(self):
        """Unknown category value must raise."""
        args = dict(
            name='testpolicy',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='category_lookup_all',
                        condition_option_category=['Definitely Not A Category']
                    )]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert 'condition_option_category' in str(err.exception)

    def test_condition_type_portrange(self):
        """client_port_match with condition_option_portrange produces range port option."""
        args = dict(
            name='testpolicy',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='client_port_match',
                        condition_option_ports=None,
                        condition_option_portrange=dict(port_from='100', port_to='200')
                    )]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        c = rules[0]['conditions'][0]
        assert c['type'] == 'Client Port Match'
        assert c['valueType'] == 'range'
        assert c['options']['port'] == [{'valueType': 'range', 'portFrom': '100', 'portTo': '200'}]

    def test_subnet_match_pre_8_0(self):
        """SSLO < 8.0 keeps subnet list as plain strings."""
        args = dict(
            name='testpolicy',
            sslo_version='7.5',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='client_ip_subnet_match',
                        condition_option_subnet=['10.0.0.0/24', '10.0.1.0/24']
                    )]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        c = rules[0]['conditions'][0]
        assert c['type'] == 'Client IP Subnet Match'
        assert c['options'] == {'subnet': ['10.0.0.0/24', '10.0.1.0/24']}

    def test_subnet_match_post_8_0(self):
        """SSLO >= 8.0 wraps each subnet; datagroup-looking paths get valueType=datagroup."""
        args = dict(
            name='testpolicy',
            sslo_version='9.0',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='server_ip_subnet_match',
                        condition_option_subnet=['10.0.0.0/24', '/Common/my_dg']
                    )]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        c = rules[0]['conditions'][0]
        assert c['type'] == 'Server IP Subnet Match'
        assert c['options'] == {'subnet': [
            {'valueType': 'staticValue', 'subnet': '10.0.0.0/24'},
            {'valueType': 'datagroup', 'subnet': '/Common/my_dg'},
        ]}

    def test_tcp_l7_protocol_lookup_invalid(self):
        """tcp_l7_protocol_lookup with an unknown proto must raise."""
        args = dict(
            name='testpolicy',
            sslo_version='9.0',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='tcp_l7_protocol_lookup',
                        option_tcp_protocol=['gopher'],
                        option_udp_protocol=None
                    )]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert 'TCP L7 protocol' in str(err.exception)
        assert 'gopher' in str(err.exception)

    def test_tcp_l7_protocol_lookup_http2_filtered_pre_9(self):
        """http2 is silently dropped from tcp protocols below SSLO 9.0."""
        args = dict(
            name='testpolicy',
            sslo_version='8.0',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='tcp_l7_protocol_lookup',
                        option_tcp_protocol=['http', 'http2'],
                        option_udp_protocol=None
                    )]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        proto = rules[0]['conditions'][0]['options']['protocol']
        assert 'http' in proto
        assert 'http2' not in proto

    def test_udp_l7_protocol_lookup_invalid(self):
        """udp_l7_protocol_lookup with an unknown proto must raise."""
        args = dict(
            name='testpolicy',
            sslo_version='9.0',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='udp_l7_protocol_lookup',
                        option_tcp_protocol=None,
                        option_udp_protocol=['ftp']
                    )]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert 'UDP L7 protocol' in str(err.exception)
        assert 'ftp' in str(err.exception)

    def test_tcp_and_udp_lookup_together_raises(self):
        """A rule mixing tcp_l7_protocol_lookup and udp_l7_protocol_lookup must raise."""
        args = dict(
            name='testpolicy',
            sslo_version='9.0',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[
                        dict(
                            condition_type='tcp_l7_protocol_lookup',
                            option_tcp_protocol=['http'],
                            option_udp_protocol=None,
                        ),
                        dict(
                            condition_type='udp_l7_protocol_lookup',
                            option_tcp_protocol=None,
                            option_udp_protocol=['dns'],
                        ),
                    ]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert 'tcp_l7_protocol_lookup' in msg
        assert 'udp_l7_protocol_lookup' in msg

    def test_geolocation_missing_type_or_value(self):
        """geolocation entries must contain both 'type' and 'value'."""
        # Missing 'value'
        args = dict(
            name='testpolicy',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='client_ip_geolocation',
                        geolocations=[dict(type='countryCode')]
                    )]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert "'type' and 'value'" in str(err.exception)

        # Missing 'type'
        args = dict(
            name='testpolicy',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='client_ip_geolocation',
                        geolocations=[dict(value='US')]
                    )]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert "'type' and 'value'" in str(err.exception)

    def test_geolocation_invalid_type(self):
        """Invalid geolocation type raises."""
        args = dict(
            name='testpolicy',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='server_ip_geolocation',
                        geolocations=[dict(type='galaxy', value='Milky Way')]
                    )]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        msg = str(err.exception)
        assert 'IP Geolocation' in msg
        assert 'galaxy' in msg

    def test_geolocation_datagroup_value(self):
        """Geolocation value that looks like /Common/<name> becomes valueType=datagroup."""
        args = dict(
            name='testpolicy',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='client_ip_geolocation',
                        geolocations=[dict(type='countryCode', value='/Common/my_dg')]
                    )]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        entry = rules[0]['conditions'][0]['options']['geolocations'][0]
        assert entry['valueType'] == 'datagroup'
        assert entry['matchType'] == 'countryCode'

    def test_condition_type_none_raises(self):
        """condition_type=None must raise."""
        args = dict(
            name='testpolicy',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(condition_type=None)]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert 'condition_type' in str(err.exception)

    def test_server_name_tls_clienthello_datagroup(self):
        """server_name_tls_clienthello with a /Common/<dg> path is tagged as datagroup."""
        args = dict(
            name='testpolicy',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='server_name_tls_clienthello',
                        condition_option_server_name=[
                            dict(type='f5keyequalf5', value='/Common/sni_dg')
                        ]
                    )]
                )
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        entry = rules[0]['conditions'][0]['options']['value'][0]
        assert entry == {
            'matchType': 'f5keyequalf5',
            'pattern': '/Common/sni_dg',
            'valueType': 'datagroup'
        }

    def test_server_cert_issuer_dn_and_san(self):
        """server_cert_issuer_dn and server_cert_subject_san resolve to correct types."""
        args = dict(
            name='testpolicy',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='server_cert_issuer_dn',
                        condition_option_cert=[dict(type='f5keyequalf5', value='CN=ca.example.com')]
                    )]
                ),
                dict(
                    name='r2', match_type='match_any',
                    policy_action='reject',
                    ssl_action=None, service_chain=None,
                    conditions=[dict(
                        condition_type='server_cert_subject_san',
                        condition_option_cert=[dict(type='f5keysubstringf5', value='example')]
                    )]
                ),
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        assert rules[0]['conditions'][0]['type'] == 'Server Certificate (Issuer DN)'
        assert rules[1]['conditions'][0]['type'] == 'Server Certificate (SANs)'

    # Policy_action additional coverage
    def test_redirect_missing_url_raises(self):
        """policy_action='redirect' but redirect_url=None must raise."""
        args = dict(
            name='testpolicy',
            sslo_version='11.1',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='redirect',
                    redirect_url=None,
                    ssl_action=None, service_chain=None,
                    conditions=[]
                )
            ]
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.policy_rules
        assert "'redirect_url'" in str(err.exception)

    def test_redirect_service_chain_prefix(self):
        """redirect action prepends ssloSC_ if missing, keeps prefix if present."""
        args = dict(
            name='testpolicy',
            sslo_version='11.1',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='redirect',
                    redirect_url='https://x.example.com',
                    ssl_action=None,
                    service_chain='foo',
                    conditions=[]
                ),
                dict(
                    name='r2', match_type='match_any',
                    policy_action='redirect',
                    redirect_url='https://y.example.com',
                    ssl_action=None,
                    service_chain='ssloSC_bar',
                    conditions=[]
                ),
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        assert rules[0]['actionOptions']['serviceChain'] == 'ssloSC_foo'
        assert rules[1]['actionOptions']['serviceChain'] == 'ssloSC_bar'

    def test_allow_action_service_chain_prefix(self):
        """allow action prepends ssloSC_ if missing, keeps prefix if present."""
        args = dict(
            name='testpolicy',
            policy_rules=[
                dict(
                    name='r1', match_type='match_any',
                    policy_action='allow',
                    ssl_action='bypass',
                    service_chain='foo',
                    conditions=[]
                ),
                dict(
                    name='r2', match_type='match_any',
                    policy_action='allow',
                    ssl_action='intercept',
                    service_chain='ssloSC_bar',
                    conditions=[]
                ),
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        assert rules[0]['actionOptions']['serviceChain'] == 'ssloSC_foo'
        assert rules[0]['actionOptions']['ssl'] == 'bypass'
        assert rules[1]['actionOptions']['serviceChain'] == 'ssloSC_bar'
        assert rules[1]['actionOptions']['ssl'] == 'intercept'

    def test_service_chain_empty_string_not_prefixed(self):
        """Regression: empty service_chain string ('' or None) must NOT be turned into 'ssloSC_'.

        Covers both `allow` and `redirect` branches that historically would emit
        'ssloSC_' (i.e. prefix + empty) when the user supplied an empty string.
        """
        args = dict(
            name='testpolicy',
            sslo_version='11.1',
            policy_rules=[
                # allow + empty string
                dict(
                    name='r_allow_empty', match_type='match_any',
                    policy_action='allow',
                    ssl_action='bypass',
                    service_chain='',
                    conditions=[]
                ),
                # allow + None
                dict(
                    name='r_allow_none', match_type='match_any',
                    policy_action='allow',
                    ssl_action='bypass',
                    service_chain=None,
                    conditions=[]
                ),
                # redirect + empty string
                dict(
                    name='r_redirect_empty', match_type='match_any',
                    policy_action='redirect',
                    redirect_url='https://block.example.com',
                    ssl_action=None,
                    service_chain='',
                    conditions=[]
                ),
                # redirect + None
                dict(
                    name='r_redirect_none', match_type='match_any',
                    policy_action='redirect',
                    redirect_url='https://block.example.com',
                    ssl_action=None,
                    service_chain=None,
                    conditions=[]
                ),
            ]
        )
        p = ModuleParameters(params=args)
        rules = p.policy_rules
        for rule in rules[:4]:
            assert rule['actionOptions']['serviceChain'] == '', (
                f"{rule['name']}: serviceChain must be '' not "
                f"{rule['actionOptions']['serviceChain']!r}"
            )

    def test_default_rule_service_chain_empty_not_prefixed(self):
        """Regression: default_rule.service_chain='' must stay '' (not 'ssloSC_')."""
        args = dict(
            name='testpolicy',
            default_rule=dict(
                allow_block='allow',
                tls_intercept='bypass',
                service_chain='',
            ),
            policy_rules=[]
        )
        p = ModuleParameters(params=args)
        # The property short-circuits on a falsy value and returns None,
        # which _process_default_rule then renders as ''.
        assert p.default_rule_service_chain is None
        rules = p.policy_rules
        assert rules[-1]['name'] == 'All Traffic'
        assert rules[-1]['actionOptions']['serviceChain'] == ''

    # default_rule edge cases
    def test_default_rule_service_chain_already_prefixed(self):
        """default_rule.service_chain that already has ssloSC_ is not double-prefixed."""
        args = dict(
            name='testpolicy',
            default_rule=dict(
                allow_block='allow',
                tls_intercept='bypass',
                service_chain='ssloSC_existing'
            ),
            policy_rules=[]
        )
        p = ModuleParameters(params=args)
        assert p.default_rule_service_chain == 'ssloSC_existing'
        # The processed rule list should include the All Traffic default rule with that chain
        rules = p.policy_rules
        assert rules[-1]['name'] == 'All Traffic'
        assert rules[-1]['actionOptions']['serviceChain'] == 'ssloSC_existing'

    # proxy_connect / pools edge cases
    def test_proxy_connect_with_pool_name(self):
        """proxy_connect.pool_name should produce create=False with the supplied name and no pools entry."""
        args = dict(
            name='testpolicy',
            proxy_connect=dict(
                username='testuser',
                password='secret',
                pool_name='/Common/existing_pool',
            )
        )
        p = ModuleParameters(params=args)
        assert p.proxy_connect == {
            'isProxyChainEnabled': True,
            'username': 'testuser',
            'password': 'secret',
            'pool': {'create': False, 'members': [], 'name': '/Common/existing_pool'},
        }
        assert p.pools == {}

    def test_proxy_connect_invalid_port_raises(self):
        """pool_members with an out-of-range port must raise via _port_check."""
        args = dict(
            name='testpolicy',
            proxy_connect=dict(
                username='u',
                password='',
                pool_members=[dict(ip='198.19.64.30', port=99999)],
            )
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.proxy_connect
        assert '0 - 65535' in str(err.exception)

    # timeout boundary + divisor selection (all 4 cases in one test)
    def test_timeout(self):
        """timeout: <10 or >1800 raises; <=99 -> divisor=10; >99 -> divisor=100."""
        with self.assertRaises(F5ModuleError) as err:
            ModuleParameters(params=dict(name='t', timeout=5)).timeout
        assert '10 and 1800' in str(err.exception)

        with self.assertRaises(F5ModuleError) as err:
            ModuleParameters(params=dict(name='t', timeout=2000)).timeout
        assert '10 and 1800' in str(err.exception)

        assert ModuleParameters(params=dict(name='t', timeout=50)).timeout == (5, 10)
        assert ModuleParameters(params=dict(name='t', timeout=300)).timeout == (3, 100)


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
        self.p4 = patch('time.time')
        self.p4.start()
        self.p4.return_value = 0
        self.p5 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_policy.check_sslo_provisioned')
        self.p5.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()
        self.p5.stop()

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
        # mm.getsslo_version = Mock(
        #     return_value=dict(code=200, contents=float("9.1")))
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

        assert results['policy_rules'] == [{'index': 1, 'name': 'testrule', 'operation': 'OR', 'mode': 'edit', 'action': 'reject',
                                            'actionOptions': {'ssl': '', 'serviceChain': '', 'urlRedirect': ''},
                                            'conditions':
                                                [{'index': 11, 'type': 'Category Lookup', 'options':
                                                    {'category': ['Financial Data and Services', 'General Email']}},
                                                 {'index': 21, 'type': 'Client Port Match', 'options': {'port': ['80', '90']}},
                                                 {'index': 31, 'type': 'Client IP Geolocation',
                                                  'options':
                                                      {'geolocations': [{'matchType': 'countryCode', 'value': 'US',
                                                                         'valueType': 'staticValue'},
                                                                        {'matchType': 'countryCode', 'value': 'UK',
                                                                         'valueType': 'staticValue'}]}}]},
                                           {'index': 41, 'name': 'testrule2', 'operation': 'AND', 'mode': 'edit', 'action': 'reject',
                                            'actionOptions': {'ssl': '', 'serviceChain': '', 'urlRedirect': ''},
                                            'conditions': [{'index': 51, 'type': 'Category Lookup',
                                                            'options': {
                                                                'category': ['Financial Data and Services',
                                                                             'General Email']}}]},
                                           {'name': 'All Traffic', 'action': 'allow', 'mode': 'edit',
                                            'actionOptions': {'ssl': 'bypass', 'serviceChain': ''}, 'isDefault': True}]

    def test_modify_policy_service_object(self, *args):
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

        exists = dict(code=200, contents=load_fixture('load_sslo_policy.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_policy_modify_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_policy_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['policy_rules'] == [{'index': 1, 'name': 'testrule', 'operation': 'OR', 'mode': 'edit',
                                            'action': 'reject',
                                            'actionOptions': {'ssl': '', 'serviceChain': '', 'urlRedirect': ''},
                                            'conditions':
                                                [{'index': 11, 'type': 'Category Lookup', 'options':
                                                    {'category': ['Financial Data and Services', 'General Email']}},
                                                 {'index': 21, 'type': 'Client Port Match',
                                                  'options': {'port': ['80', '90']}},
                                                 {'index': 31, 'type': 'Client IP Geolocation',
                                                  'options': {'geolocations': [
                                                      {'matchType': 'countryCode', 'value': 'US',
                                                       'valueType': 'staticValue'},
                                                      {'matchType': 'countryCode', 'value': 'UK',
                                                       'valueType': 'staticValue'}]}}]},
                                           {'index': 41, 'name': 'testrule2', 'operation': 'AND', 'mode': 'edit', 'action': 'reject',
                                            'actionOptions': {'ssl': '', 'serviceChain': '', 'urlRedirect': ''},
                                            'conditions': [{'index': 51, 'type': 'Category Lookup',
                                                            'options': {'category': ['Financial Data and Services',
                                                                                     'General Email']}}]},
                                           {'name': 'All Traffic', 'action': 'allow', 'mode': 'edit',
                                            'actionOptions': {'ssl': 'bypass', 'serviceChain': ''}, 'isDefault': True}]

    # state=absent paths
    def test_absent_when_policy_exists(self):
        """state=absent and policy exists triggers DELETE flow and returns changed=True."""
        set_module_args(dict(name='testpolicy', state='absent'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=True)
        mm.block_id = 'fake-block-id'
        mm.client.post = Mock(return_value=dict(code=202, contents=dict(id='task-id')))
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_policy_modify_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        mm.client.post.assert_called_once()

    def test_absent_when_policy_not_exist(self):
        """state=absent and policy missing returns changed=False without calling post."""
        set_module_args(dict(name='testpolicy', state='absent'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=False)
        mm.client.post = Mock()

        results = mm.exec_module()

        assert results['changed'] is False
        mm.client.post.assert_not_called()

    # default_rule honoured during create
    def test_create_with_user_default_rule(self):
        """A user-supplied default_rule must be used verbatim (no auto-append of 'allow/bypass')."""
        set_module_args(dict(
            name='testpolicy',
            default_rule=dict(
                allow_block='block',
                tls_intercept='intercept',
                service_chain='my_chain',
            ),
            policy_rules=[
                dict(
                    name='r1', match_type='match_any', policy_action='reject',
                    conditions=[dict(condition_type='ssl_check')]
                )
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

        rules = results['policy_rules']
        assert rules[-1]['name'] == 'All Traffic'
        assert rules[-1]['action'] == 'block'
        assert rules[-1]['actionOptions']['ssl'] == 'intercept'
        assert rules[-1]['actionOptions']['serviceChain'] == 'ssloSC_my_chain'

    # add_sslo_9x_support port-match transformation
    def test_add_sslo_9x_support_port_match_transformation(self):
        """add_sslo_9x_support rewrites port-match conditions to valueAndDatagroup form."""
        set_module_args(dict(name='testpolicy'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        params = {
            'policy_rules': [
                {
                    'name': 'r1', 'action': 'reject',
                    'conditions': [
                        {'type': 'Client Port Match',
                         'options': {'port': ['80', '443', '21', '25', '8080', '/Common/my_dg']}}
                    ]
                }
            ]
        }
        out = mm.add_sslo_9x_support(params)
        cond = out['policy_rules'][0]['conditions'][0]
        assert cond['valueType'] == 'valueAndDatagroup'
        ports = cond['options']['port']
        assert {'port': '80', 'valueType': 'staticValue', 'type': 'HTTP'} in ports
        assert {'port': '443', 'valueType': 'staticValue', 'type': 'HTTPS'} in ports
        assert {'port': '21', 'valueType': 'staticValue', 'type': 'FTP'} in ports
        assert {'port': '25', 'valueType': 'staticValue', 'type': 'SMTP'} in ports
        assert {'port': '8080', 'valueType': 'staticValue', 'type': 'Others'} in ports
        assert {'port': '/Common/my_dg', 'valueType': 'datagroup'} in ports

    # dump_json bypasses network and returns the rendered output
    def test_create_dump_json(self):
        """dump_json=True must skip client.post, return changed=False, expose 'json' result."""
        set_module_args(dict(
            name='testpolicy',
            dump_json=True,
            policy_rules=[
                dict(
                    name='r1', match_type='match_any', policy_action='reject',
                    conditions=[dict(condition_type='ssl_check')]
                )
            ]
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=False)
        mm.client.post = Mock()

        results = mm.exec_module()

        assert results['changed'] is False
        assert 'json' in results
        mm.client.post.assert_not_called()

    # SSLO version sanity check
    def test_unsupported_sslo_version_raises(self):
        """check_sslo_version() refuses versions below min_sslo_version."""
        self.m3.return_value = '5.0'  # below min 7.5
        set_module_args(dict(name='testpolicy'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        assert 'Unsupported SSL Orchestrator version' in str(err.exception)

    # End-to-end create for Inbound + LTM scenario
    def test_create_inbound_ltm(self):
        """inbound+ltm with an allowed action/ssl_action/condition produces the expected payload."""
        set_module_args(dict(
            name='testpolicy',
            policy_consumer='inbound',
            policy_provider='ltm',
            policy_rules=[
                dict(
                    name='inbound_rule',
                    match_type='match_any',
                    policy_action='allow',
                    ssl_action='intercept',
                    service_chain=None,
                    conditions=[dict(
                        condition_type='ip_protocol',
                        condition_option_ip_protocol='tcp'
                    )]
                )
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
        assert results['policy_consumer'] == 'Inbound'
        assert results['policy_provider'] == 'ltm'
        rules = results['policy_rules']
        assert rules[0]['name'] == 'inbound_rule'
        assert rules[0]['action'] == 'allow'
        assert rules[0]['actionOptions']['ssl'] == 'intercept'
        assert rules[0]['conditions'][0]['type'] == 'IP Protocol'
        # default All Traffic rule auto-appended
        assert rules[-1]['name'] == 'All Traffic'

    def test_update_idempotent_policy(self):
        set_module_args(dict(name='testpolicy'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.read_current_from_device = Mock(return_value=ApiParameters(params={
            'policyConsumer': {'type': 'Outbound'},
            'policyProvider': 'prp',
            'rules': [],
            'serverCertStatusCheck': False,
            'proxyConfigurations': {},
            'pools': {},
        }))
        mm.update_on_device = Mock()

        results = mm.exec_module()

        assert results['changed'] is False
        mm.update_on_device.assert_not_called()

    def test_exists_error_raises(self):
        set_module_args(dict(name='testpolicy'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='exists failed'))

        with self.assertRaisesRegex(F5ModuleError, 'exists failed'):
            mm.exists()

    def test_create_on_device_error_raises(self):
        set_module_args(dict(name='testpolicy'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.version = '8.0'
        mm.changes = Mock(to_return=Mock(return_value={'policy_rules': []}))
        mm.client.post = Mock(return_value=dict(code=500, contents='create failed'))

        with patch.object(bigip_sslo_config_policy, 'process_json', return_value={}):
            with self.assertRaisesRegex(F5ModuleError, 'create failed'):
                mm.create_on_device()

    def test_update_on_device_error_raises(self):
        set_module_args(dict(name='testpolicy'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.version = '8.0'
        mm.changes = Mock(to_return=Mock(return_value={'policy_rules': []}))
        mm.have = ApiParameters(params={
            'policyConsumer': {'type': 'Outbound'}, 'rules': [], 'serverCertStatusCheck': False,
            'proxyConfigurations': {}, 'pools': {},
        })
        mm.client.post = Mock(return_value=dict(code=500, contents='update failed'))

        with patch.object(bigip_sslo_config_policy, 'process_json', return_value={}):
            with self.assertRaisesRegex(F5ModuleError, 'update failed'):
                mm.update_on_device()

    def test_read_current_from_device_errors_raise(self):
        set_module_args(dict(name='testpolicy'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)

        mm.client.get = Mock(return_value=dict(code=500, contents='read failed'))
        with self.assertRaisesRegex(F5ModuleError, 'read failed'):
            mm.read_current_from_device()

        mm.client.get = Mock(return_value=dict(code=200, contents={'items': []}))
        with self.assertRaisesRegex(F5ModuleError, 'items'):
            mm.read_current_from_device()

    def test_check_task_on_device_error_raises(self):
        set_module_args(dict(name='testpolicy'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='task failed'))

        with self.assertRaisesRegex(F5ModuleError, 'task failed'):
            mm._check_task_on_device('task-id')

    def test_wait_for_task_error_and_timeout_raise(self):
        set_module_args(dict(name='testpolicy', timeout=10))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.operation = 'CREATE'
        mm._check_task_on_device = Mock(return_value={'state': 'ERROR', 'error': 'operation failed'})
        mm.delete_failed_operation_on_device = Mock()

        with self.assertRaisesRegex(F5ModuleError, 'operation failed'):
            mm.wait_for_task('task-id')
        mm.delete_failed_operation_on_device.assert_called_once_with('task-id')

        mm._check_task_on_device = Mock(return_value={'state': 'RUNNING'})
        with self.assertRaisesRegex(F5ModuleError, 'Module timeout reached'):
            mm.wait_for_task('task-id')

    def test_remove_from_device_error_raises(self):
        set_module_args(dict(name='testpolicy'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.operation = 'DELETE'
        mm.version = '8.0'
        mm.client.post = Mock(return_value=dict(code=500, contents='delete failed'))

        with patch.object(bigip_sslo_config_policy, 'process_json', return_value={}):
            with self.assertRaisesRegex(F5ModuleError, 'delete failed'):
                mm.remove_from_device()

    def test_main_function_success(self):
        module = Mock(_socket_path='/tmp/socket')
        manager = Mock()
        manager.exec_module.return_value = {'changed': False}
        with patch.object(bigip_sslo_config_policy, 'AnsibleModule', return_value=module), \
                patch.object(bigip_sslo_config_policy, 'Connection'), \
                patch.object(bigip_sslo_config_policy, 'HAS_NETADDR', True), \
                patch.object(bigip_sslo_config_policy, 'HAS_PACKAGING', True), \
                patch.object(bigip_sslo_config_policy, 'ModuleManager', return_value=manager):
            bigip_sslo_config_policy.main()

        module.exit_json.assert_called_once_with(changed=False)

    def test_main_function_failed(self):
        module = Mock(_socket_path='/tmp/socket')
        manager = Mock()
        manager.exec_module.side_effect = F5ModuleError('policy failed')
        with patch.object(bigip_sslo_config_policy, 'AnsibleModule', return_value=module), \
                patch.object(bigip_sslo_config_policy, 'Connection'), \
                patch.object(bigip_sslo_config_policy, 'HAS_NETADDR', True), \
                patch.object(bigip_sslo_config_policy, 'HAS_PACKAGING', True), \
                patch.object(bigip_sslo_config_policy, 'ModuleManager', return_value=manager):
            bigip_sslo_config_policy.main()

        module.fail_json.assert_called_once_with(msg='policy failed')
