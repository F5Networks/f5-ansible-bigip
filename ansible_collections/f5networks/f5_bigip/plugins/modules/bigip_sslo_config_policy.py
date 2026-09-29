#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_config_policy
short_description: Manage an SSL Orchestrator security policy
description:
  - Use to manage an SSL Orchestrator security policy.
version_added: "1.7.0"
options:
  name:
    description:
      - Specifies the name of the security policy.
      - Configuration auto-prepends "ssloP_" to the policy.
      - The policy name should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  policy_consumer:
    description:
      - Specifies the type of policy.
    type: str
    choices:
      - outbound
      - inbound
    default: outbound
  policy_provider:
    description:
      - Specifies the policy provider backing the security policy.
      - When C(policy_consumer) is C(outbound), C(prp) is the only valid value and is
        applied automatically; supplying anything else raises an error.
      - When C(policy_consumer) is C(inbound), defaults to C(prp); C(ltm) is also allowed.
      - Each inbound scenario restricts the supported C(condition_type) values, and
        C(inbound) + C(ltm) further restricts C(policy_action) to C(allow) or C(abort)
        with C(ssl_action) limited to C(intercept). Invalid combinations raise an error.
    type: str
    choices:
      - prp
      - ltm
  default_rule:
    description:
      - Specifies the settings for the default C(All Traffic) security policy rule.
      - When creating a new policy, the rule is created with default values.
      - "When modifying existing policy, all values should be defined or they are replaced by default values (see below)."
    type: dict
    suboptions:
      allow_block:
        description:
          - Defines the behavior for the default All Traffic rule.
          - If not specified, the C(allow) option is set.
        type: str
        choices:
          - allow
          - block
      tls_intercept:
        description:
          - Defines the TLS behavior for the default All Traffic rule.
          - If not specified, the C(bypass) option is set.
        type: str
        choices:
          - bypass
          - intercept
      service_chain:
        description:
          - Defines the service chain to attach to the default All Traffic rule.
          - If not specified, the C('') value is set.
        type: str
    version_added: "1.8.0"
  proxy_connect:
    description:
      - Specifies the proxy-connect settings, as required, to establish an upstream proxy chain egress.
    type: dict
    suboptions:
      pool_members:
        description:
          - Defines pool members which we want to associate for the new pool.
          - Mutually exclusive with the C(pool_name) parameter.
        type: list
        elements: dict
        suboptions:
           ip:
             description:
               - IP address of the pool member you want to add.
             type: str
             required: True
           port:
             description:
               - Port number to be associated with the pool member IP address.
             type: int
      pool_name:
        description:
          - Defines an existing pool name for the proxy connection. Specify with a partition.
          - Mutually exclusive with C(pool_members).
        type: str
      username:
        description:
          - Defines the username for the proxy connection.
        type: str
      password:
        description:
          - Defines the password pool for the proxy connection.
        type: str
      update_password:
        description:
          - When C(true), the password is updated on the device. When C(false), the existing
            password is left unchanged even if C(password) is specified.
          - Set to C(true) only when you intend to change the proxy chain password.
        type: bool
        default: false
  server_cert_check:
    description:
      - Enables or disables server certificate validation.
    type: bool
  policy_rules:
    description:
      - Defines the policy rules to apply to the security policy, in defined order.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Defines the name of the policy rule.
        type: str
      match_type:
        description:
          - Defines the match type when multiple conditions are applied to a single rule.
        type: str
        choices:
          - match_any
          - match_all
      conditions:
        description:
          - Defines the list of conditions within this rule.
        type: list
        elements: dict
        suboptions:
          condition_type:
            description:
              - Defines the name of the policy rule.
            type: str
            choices:
              - category_lookup_all
              - category_lookup_sni
              - category_lookup_httpconnect
              - ssl_check
              - client_port_match
              - server_port_match
              - client_ip_subnet_match
              - server_ip_subnet_match
              - tcp_l7_protocol_lookup
              - udp_l7_protocol_lookup
              - client_ip_geolocation
              - server_ip_geolocation
              - client_ip_reputation
              - server_ip_reputation
              - client_vlan
              - ip_protocol
              - server_cert_subject_dn
              - server_cert_issuer_dn
              - server_cert_subject_san
              - server_name_tls_clienthello
              - url_match
          condition_option_category:
            description:
              - A list of URL categories (ex. "Financial and Data Services").
              - Use when C(condition_type) matches C(category_lookup_all) or C(category_lookup_sni).
            type: list
            elements: str
          geolocations:
            description:
              - A list of 'type' and 'value' keys, where type can be 'countryCode', 'countryName', 'continent', or 'state'.
              - Use when C(condition_type) matches C(client_ip_geolocation) or C(server_ip_geolocation).
            type: list
            elements: dict
          condition_option_ports:
            description:
              - Defines a list of ports.
              - Use when C(condition_type) matches C(client_port_match) or C(server_port_match).
            type: list
            elements: str
          condition_option_portrange:
            description:
              - Defines a port-range with using keys C(port_from) and C(port_to).
              - Use when C(condition_type) matches C(client_port_match) or C(server_port_match).
            type: dict
            suboptions:
              port_from:
                description:
                  - Starting port number in the port range.
                type: str
              port_to:
                description:
                  - Ending port number in the port range.
                type: str
          condition_option_subnet:
            description:
              - Defines a list of IP subnets.
              - Use when C(condition_type) matches C(client_ip_subnet_match) or C(server_ip_subnet_match).
            type: list
            elements: str
          option_tcp_protocol:
            description:
              - Defines a list of TCP protocols to be used with C(tcp_l7_protocol_lookup).
            type: list
            elements: str
          option_udp_protocol:
            description:
              - Defines a list of UDP protocols you want used with C(udp_l7_protocol_lookup).
            type: list
            elements: str
          condition_option_ip_reputation:
            description:
              - Defines the IP reputation match mode.
              - C(good) matches known-good sources; C(bad) matches known-bad sources.
              - C(category) matches specific threat categories listed in C(condition_option_ip_reputation_category).
              - Use when C(condition_type) is C(client_ip_reputation) or C(server_ip_reputation).
            type: str
            choices:
              - good
              - bad
              - category
          condition_option_ip_reputation_category:
            description:
              - A list of IP reputation threat categories to match.
              - Required when C(condition_option_ip_reputation) is C(category).
              - Valid values include C(Spam Sources), C(Windows Exploits), C(Web Attacks), C(Scanners),
                C(BotNets), C(Denial Of Service), C(Infected Sources), C(Phishing), C(Proxy),
                C(Cloud Providers), C(Mobile Threats), C(Tor Proxy).
            type: list
            elements: str
          condition_option_vlan:
            description:
              - Defines a list of VLAN names (e.g. C(/Common/internal)).
              - Supports data group references using the format C(/partition/datagroup_name).
              - Use when C(condition_type) is C(client_vlan).
            type: list
            elements: str
          condition_option_ip_protocol:
            description:
              - Defines a single IP protocol name.
              - Use when C(condition_type) is C(ip_protocol).
            type: str
            choices:
              - tcp
              - udp
          condition_option_cert:
            description:
              - A list of C(type) and C(value) keys for certificate DN or SAN matching.
              - C(type) accepts API values C(f5keyequalf5), C(f5keysubstringf5), C(f5keyprefixf5), C(f5keysuffixf5), C(f5keyglobalf5).
              - Data group references (e.g. C(/Common/my_dg)) always use C(f5keyequalf5) regardless of C(type).
              - Use when C(condition_type) is C(server_cert_subject_dn), C(server_cert_issuer_dn), or C(server_cert_subject_san).
            type: list
            elements: dict
          condition_option_server_name:
            description:
              - A list of C(type) and C(value) keys for TLS ClientHello SNI matching.
              - C(type) accepts API values C(f5keyequalf5), C(f5keysubstringf5), C(f5keyprefixf5), C(f5keysuffixf5), C(f5keyglobalf5).
              - Use when C(condition_type) is C(server_name_tls_clienthello).
            type: list
            elements: dict
          condition_option_url:
            description:
              - A list of C(type) and C(value) keys for URL matching.
              - C(type) accepts API values C(f5keyequalf5), C(f5keysubstringf5), C(f5keyprefixf5), C(f5keysuffixf5), C(f5keyglobalf5).
              - Use when C(condition_type) is C(url_match).
            type: list
            elements: dict
      policy_action:
        description:
          - Defines the policy action applied for this rule.
          - When C(redirect), the traffic is redirected to the URL specified in C(redirect_url).
          - The C(redirect) action requires SSLO version 11.1 or later.
        type: str
        choices:
          - allow
          - reject
          - abort
          - redirect
      ssl_action:
        description:
          - Defines the TLS intercept/bypass behavior for this rule.
          - Required when C(policy_action) is C(allow), unless the rule contains a condition
            that runs in the HTTP or L7 protocol phase (for example C(url_match),
            C(tcp_l7_protocol_lookup), or C(udp_l7_protocol_lookup)).
          - Not valid when the rule contains a condition that runs in the HTTP or L7 protocol phase
            (for example C(url_match), C(tcp_l7_protocol_lookup), or C(udp_l7_protocol_lookup)),
            and must be omitted.
          - When C(policy_action) is C(redirect), this option is ignored; C(ssl_action) is always
            set to C(intercept) and cannot be overridden.
        type: str
        choices:
          - bypass
          - intercept
      service_chain:
        description:
          - Defines the service chain to attach to this rule.
          - Optional in all cases where it is valid.
          - Not valid when the rule contains a condition that runs in the HTTP protocol phase
            (for example C(url_match)), regardless of C(policy_action), and must be omitted.
        type: str
      redirect_url:
        description:
          - Defines the URL to redirect traffic to when C(policy_action) is C(redirect).
          - Must be a valid URL starting with C(http://) or C(https://).
          - Required when C(policy_action) is C(redirect).
          - Requires SSLO version 11.1 or later.
          - When C(policy_action) is C(redirect), C(ssl_action) is always set to C(intercept) and cannot be overridden.
        type: str
  dump_json:
    description:
      - Sets the module to output a JSON blob for further consumption.
      - When C(true) does not make any changes on the device and always returns C(changed=False).
      - The output provided is idempotent in nature, meaning if there are no changes made during
        C(MODIFY) on an existing service, no JSON output is generated.
    type: bool
    default: false
  timeout:
    description:
      - The amount of time, to wait for the C(CREATE) or C(MODIFY) task to complete, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
  state:
    description:
      - When C(state) is C(present), ensures the policy is created or modified.
      - When C(state) is C(absent), ensures the policy is removed.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Ravinder Reddy(@chinthalapalli)
  - Kevin Stewart (@kevingstewart)
'''

EXAMPLES = r'''
- name: SSLO config policy
  bigip_sslo_config_policy:
    name: "testpolicy"
    server_cert_check: true
    proxy_connect:
      username: "testuser"
      password: ""
      pool_members:
        - ip: "192.168.30.10"
          port: 100
    policy_rules:
      - name: "testrule"
        match_type: "match_any"
        policy_action: "reject"
        conditions:
          - condition_type: "category_lookup_all"
            condition_option_category:
              - "Financial Data and Services"
              - "General Email"
          - condition_type: "client_port_match"
            condition_option_ports:
              - "80"
              - "90"
          - condition_type: "client_ip_geolocation"
            geolocations:
              - type: "countryCode"
                value: "US"
              - type: "countryCode"
                value: "UK"
      - name: "testrule2"
        match_type: "match_all"
        policy_action: "reject"
        conditions:
          - condition_type: "category_lookup_all"
            condition_option_category:
              - "Financial Data and Services"
              - "General Email"
          - condition_type: "client_port_match"
            condition_option_ports:
              - "80"
              - "90"
'''

RETURN = r'''
# only common fields returned
'''

import re
import time
import random
import ipaddress
import traceback

try:
    from packaging.version import Version
except ImportError:
    HAS_PACKAGING = False
    Version = None
    PACKAGING_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_PACKAGING = True
    PACKAGING_IMPORT_ERROR = None

try:
    from netaddr import IPAddress
except ImportError:
    HAS_NETADDR = False
    IPAddress = None
    NETADDR_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_NETADDR = True
    NETADDR_IMPORT_ERROR = None

from ansible.module_utils.basic import (
    AnsibleModule, missing_required_lib
)
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, sslo_version, check_sslo_provisioned
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, process_json
)

from ..module_utils.constants import (
    min_sslo_version, max_sslo_version
)
from ..module_utils.compare import compare_complex_list
from ..module_utils.sslo_templates.sslo_config_policy import (
    create_modify, delete
)


def generate_pfid(prefix):
    return prefix + str(int(time.time() * 1000)) + str(random.randint(0, 999))


def obfuscate(s):
    return "".join(f"{ord(c):03d}" for c in s)


def deobfuscate(s):
    return "".join(chr(int(s[i:i + 3])) for i in range(0, len(s), 3))


condition_type = {'category_lookup_all': 'Category Lookup',
                  'category_lookup_sni': "SNI Category Lookup",
                  'category_lookup_httpconnect': "HTTP Connect Category Lookup",
                  'ssl_check': "SSL Check",
                  'client_port_match': "Client Port Match",
                  'server_port_match': "Server Port Match",
                  'client_ip_subnet_match': "Client IP Subnet Match",
                  'server_ip_subnet_match': "Server IP Subnet Match",
                  'tcp_l7_protocol_lookup': "TCP L7 Protocol Lookup",
                  'udp_l7_protocol_lookup': "UDP L7 Protocol Lookup",
                  'client_ip_geolocation': "Client IP Geolocation",
                  'server_ip_geolocation': "Server IP Geolocation",
                  'client_ip_reputation': "Client IP Reputation",
                  'server_ip_reputation': "Server IP Reputation",
                  'client_vlan': "Client VLANs",
                  'ip_protocol': "IP Protocol",
                  'server_cert_subject_dn': "Server Certificate (Subject DN)",
                  'server_cert_issuer_dn': "Server Certificate (Issuer DN)",
                  'server_cert_subject_san': "Server Certificate (SANs)",
                  'server_name_tls_clienthello': "Server Name (TLS ClientHello)",
                  'url_match': "URL Branching"
                  }

condition_type_list = ['category_lookup_all', 'category_lookup_sni', 'category_lookup_httpconnect', 'ssl_check',
                       'client_port_match', 'server_port_match', 'client_ip_subnet_match', 'server_ip_subnet_match',
                       'tcp_l7_protocol_lookup', 'udp_l7_protocol_lookup', 'client_ip_geolocation', 'server_ip_geolocation',
                       'client_ip_reputation', 'server_ip_reputation', 'client_vlan', 'ip_protocol',
                       'server_cert_subject_dn', 'server_cert_issuer_dn', 'server_cert_subject_san',
                       'server_name_tls_clienthello', 'url_match']

category_list = ['category_lookup_all', 'category_lookup_sni', 'category_lookup_httpconnect']
port_list = ['client_port_match', 'server_port_match']
port_map = ['Client Port Match', 'Server Port Match']
subnet_list = ['client_ip_subnet_match', 'server_ip_subnet_match']
protocol_list = ['tcp_l7_protocol_lookup', 'udp_l7_protocol_lookup']
geolocation_list = ['client_ip_geolocation', 'server_ip_geolocation']
reputation_list = ['client_ip_reputation', 'server_ip_reputation']
cert_list = ['server_cert_subject_dn', 'server_cert_issuer_dn', 'server_cert_subject_san']

# HTTP Phase Conditions
http_phase_condition_types = {'url_match'}

# L7 Phase Conditions
l7_phase_condition_types = {'tcp_l7_protocol_lookup', 'udp_l7_protocol_lookup'}

# Per-scenario allow-lists keyed by (policy_consumer, policy_provider).
allowed_conditions_matrix = {
    ('Outbound', 'prp'): list(condition_type_list),
    ('Inbound', 'prp'): [
        'client_port_match', 'server_port_match',
        'client_ip_subnet_match', 'server_ip_subnet_match',
        'tcp_l7_protocol_lookup', 'udp_l7_protocol_lookup',
        'client_ip_geolocation', 'server_ip_geolocation',
        'client_ip_reputation', 'server_ip_reputation',
        'client_vlan', 'ip_protocol',
        'server_cert_subject_dn', 'server_cert_issuer_dn', 'server_cert_subject_san',
        'server_name_tls_clienthello', 'ssl_check', 'url_match',
    ],
    ('Inbound', 'ltm'): [
        'client_port_match', 'server_port_match',
        'client_ip_subnet_match', 'server_ip_subnet_match',
        'client_ip_geolocation', 'server_ip_geolocation',
        'client_ip_reputation', 'server_ip_reputation',
        'ip_protocol',
        'server_name_tls_clienthello',
    ],
}

allowed_actions_matrix = {
    ('Outbound', 'prp'): ['allow', 'reject', 'abort', 'redirect'],
    ('Inbound', 'prp'): ['allow', 'reject', 'abort', 'redirect'],
    ('Inbound', 'ltm'): ['allow', 'abort'],
}

allowed_ssl_actions_matrix = {
    ('Inbound', 'ltm'): {None, 'intercept'},
}

ip_protocol_list = ['tcp', 'udp']

condition_category = {'general_mail': "General Email",
                      'financial_data_and_services': "Financial Data and Services"
                      }

tcp_proto_list = ["dns", "ftp", "ftps", "http", "httpConnect", "https", "imap", "imaps", "pop3", "pop3s", "smtp",
                  "smtps", "telnet", "http2"]

condition_category_list = [
    "Files Containing Passwords",
    "File Download Servers",
    "Facebook Video Upload",
    "Facebook Questions",
    "Abortion",
    "Abused Drugs",
    "Adult Content",
    "Adult Material",
    "Advanced Malware Command and Control",
    "Advanced Malware Payloads",
    "Advertisements",
    "Advocacy Groups",
    "Alcohol and Tobacco",
    "Alternative Journals",
    "Application and Software Download",
    "Bandwidth",
    "Blog Commenting",
    "Blog Posting",
    "Blogs and Personal Sites",
    "Bot Networks",
    "Business and Economy",
    "Classifieds Posting",
    "Collaboration - Office",
    "Compromised Websites",
    "Computer Security",
    "Content Delivery Networks",
    "Cultural Institutions",
    "Custom-Encrypted Uploads",
    "Drugs",
    "Dynamic Content",
    "Dynamic DNS",
    "Education",
    "Educational Institutions",
    "Educational Materials",
    "Educational Video",
    "Elevated Exposure",
    "Emerging Exploits",
    "Entertainment",
    "Entertainment Video",
    "Extended Protection",
    "Facebook Apps",
    "Facebook Chat",
    "Facebook Commenting",
    "Facebook Events",
    "Facebook Friends",
    "Facebook Games",
    "Facebook Groups",
    "Facebook Mail",
    "Facebook Photo Upload",
    "Facebook Posting",
    "Financial Data and Services",
    "Gambling",
    "Games",
    "Gay or Lesbian or Bisexual Interest",
    "General Email",
    "Government",
    "Hacking",
    "Health and Medicine",
    "Hosted Business Applications",
    "Illegal or Questionable",
    "Information Technology",
    "Instant Messaging",
    "Internet Auctions",
    "Internet Communication",
    "Internet Radio and TV",
    "Internet Telephony",
    "Intolerance",
    "Job Search",
    "Keyloggers and Monitoring",
    "Lingerie and Swimsuit",
    "LinkedIn Connections",
    "LinkedIn Jobs",
    "LinkedIn Mail",
    "LinkedIn Updates",
    "Malicious Embedded Link",
    "Malicious Embedded iFrame",
    "Malicious Web Sites",
    "Marijuana",
    "Media File Download",
    "Message Boards and Forums",
    "Militancy and Extremist",
    "Military",
    "Miscellaneous",
    "Mobile Malware",
    "Network Errors",
    "Newly Registered Websites",
    "News and Media",
    "Non-Traditional Religions",
    "Nudity",
    "Nutrition",
    "Office - Apps",
    "Office - Documents",
    "Office - Drive",
    "Office - Mail",
    "Online Brokerage and Trading",
    "Organizational Email",
    "Parked Domain",
    "Pay to Surf",
    "Peer-to-Peer File Sharing",
    "Personal Network Storage and Backup",
    "Personals and Dating",
    "Phishing and Other Frauds",
    "Political Organizations",
    "Potentially Exploited Documents",
    "Potentially Unwanted Software",
    "Prescribed Medications",
    "Private IP Addresses",
    "Pro-Choice",
    "Pro-Life",
    "Productivity",
    "Professional and Worker Organizations",
    "Proxy Avoidance",
    "Real Estate",
    "Recreation and Hobbies",
    "Reference and Research",
    "Religion",
    "Restaurants and Dining",
    "Search Engines and Portals",
    "Security",
    "Service and Philanthropic Organizations",
    "Sex",
    "Sex Education",
    "Shopping",
    "Social Networking",
    "Social Organizations",
    "Social Web - Facebook",
    "Social Web - LinkedIn",
    "Social Web - Twitter",
    "Social Web - Various",
    "Social Web - YouTube",
    "Social and Affiliation Organizations",
    "Society and Lifestyles",
    "Special Events",
    "Sport Hunting and Gun Clubs",
    "Sports",
    "Spyware and Adware",
    "Streaming Media",
    "Surveillance",
    "Suspicious Content",
    "Suspicious Embedded Link",
    "Tasteless",
    "Text and Media Messaging",
    "Traditional Religions",
    "Travel",
    "Twitter Follow",
    "Twitter Mail",
    "Twitter Posting",
    "Unauthorized Mobile Marketplaces",
    "Uncategorized",
    "Vehicles",
    "Violence",
    "Viral Video",
    "Weapons",
    "Web Analytics",
    "Web Chat",
    "Web Collaboration",
    "Web Hosting",
    "Web Images",
    "Web Infrastructure",
    "Web and Email Marketing",
    "Web and Email Spam",
    "Website Translation",
    "YouTube Commenting",
    "YouTube Sharing",
    "YouTube Video Upload",
    "Pinners"
]


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []
    updatables = [
        'proxy_connect',
        'pools',
        'policy_consumer',
        'policy_provider',
        'policy_rules',
        'server_cert_check'
    ]
    returnables = [
        'proxy_connect',
        'pools',
        'policy_consumer',
        'policy_provider',
        'policy_rules',
        'server_cert_check'
    ]


class ApiParameters(Parameters):
    @property
    def policy_consumer(self):
        return self._values['policyConsumer']['type']

    @property
    def policy_provider(self):
        return self._values.get('policyProvider')

    @property
    def policy_rules(self):
        # return self._values['rules']
        rules = list()
        for rule in self._values['rules']:
            # if 'All Traffic' != rule['name']:
            new_dict = dict()
            for key, value in rule.items():
                if str(key) == 'phase':
                    continue
                elif str(key) == 'injectServerCertMacro':
                    continue
                elif str(key) == 'injectCategorizationMacro':
                    continue
                else:
                    new_dict[key] = value
            rules.append(new_dict)
        return rules

    @property
    def server_cert_check(self):
        return self._values['serverCertStatusCheck']

    @property
    def proxy_connect(self):
        return self._values['proxyConfigurations']

    @property
    def pools(self):
        return self._values['pools']


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result


class ModuleParameters(Parameters):
    @staticmethod
    def _port_check(item):
        if 0 <= item <= 65535:
            return item
        raise F5ModuleError(
            "Valid ports must be in range 0 - 65535."
        )

    @staticmethod
    def _prefixed_service_chain(value):
        if not value:
            return ""
        if value.startswith("ssloSC_"):
            return value
        return "ssloSC_" + value

    @staticmethod
    def _build_match_pattern_list(items, label, check_datagroup=True):
        valid_match_types = {"f5keyequalf5", "f5keysubstringf5", "f5keyprefixf5", "f5keysuffixf5", "f5keyglobalf5"}
        result = []
        for opt in items:
            if "type" not in opt:
                raise F5ModuleError(
                    f"The '{label}' condition requires each item to contain a 'type' and 'value' sub-key."
                )
            if "value" not in opt:
                raise F5ModuleError(
                    f"The '{label}' condition requires each item to contain a 'type' and 'value' sub-key."
                )
            if opt["type"] not in valid_match_types:
                raise F5ModuleError(
                    f"The '{label}' match type must be one of "
                    "['f5keyequalf5', 'f5keysubstringf5', 'f5keyprefixf5', "
                    f"'f5keysuffixf5', 'f5keyglobalf5'], but '{opt['type']}' was entered."
                )
            tmp = {'matchType': opt['type'], 'pattern': opt['value']}
            if check_datagroup:
                if re.match(r'^\/\w+\/[a-zA-Z0-9\-\.\_]+$', opt['value']):
                    if opt['type'] == 'f5keyglobalf5':
                        raise F5ModuleError(
                            "Datagroup references do not support 'f5keyglobalf5' matchType."
                        )
                    tmp['valueType'] = 'datagroup'
                else:
                    tmp['valueType'] = 'staticValue'
            result.append(tmp)
        return result

    @staticmethod
    def _process_network(item):
        cidr = IPAddress(item['netmask']).netmask_bits()
        ip = f"{item['self_ip']}/{cidr}"
        network = re.sub('/[0-9]+', '', str(ipaddress.ip_network(ip, strict=False)))
        return network

    @property
    def name(self):
        name = self._values['name']
        if not name.startswith('ssloP_'):
            name = "ssloP_" + name
        return name

    @property
    def policy_consumer(self):
        result = self._values['policy_consumer']
        if result:
            return result.capitalize()

    @property
    def policy_provider(self):
        consumer = self.policy_consumer
        provider = self._values.get('policy_provider')
        if consumer == 'Outbound':
            if provider is not None and provider != 'prp':
                raise F5ModuleError(
                    "When 'policy_consumer' is 'outbound', 'policy_provider' must be 'prp' "
                    f"(or omitted); '{provider}' was entered."
                )
            return 'prp'
        if consumer == 'Inbound':
            return provider if provider else 'prp'
        return provider

    @property
    def default_rule_allow_block(self):
        if self._values['default_rule'] is None:
            return None
        return self._values['default_rule'].get('allow_block', None)

    @property
    def default_rule_tls_intercept(self):
        if self._values['default_rule'] is None:
            return None
        return self._values['default_rule'].get('tls_intercept', None)

    @property
    def default_rule_service_chain(self):
        if self._values['default_rule'] is None:
            return None
        value = self._values['default_rule'].get('service_chain', None)
        if value:
            if value.startswith("ssloSC_"):
                return value
            else:
                return "ssloSC_" + value

    @property
    def proxy_connect(self):
        if self._values['proxy_connect'] is None:
            return None
        proxy_config = dict()
        proxy_config['isProxyChainEnabled'] = True
        proxy_config['username'] = self._values['proxy_connect']['username']
        proxy_config['password'] = ""
        if self._values['proxy_connect']['password'] is not None:
            proxy_config['password'] = self._values['proxy_connect']['password']
        proxy_config_pool = dict()
        if 'pool_members' in self._values['proxy_connect'] and \
                self._values['proxy_connect']['pool_members'] is not None:
            proxy_config_pool['create'] = True
            pool_members = list()
            for mem in self._values['proxy_connect']['pool_members']:
                tmpdict = dict()
                tmpdict['ip'] = mem['ip']
                if 'port' not in mem.keys() or not mem['port']:
                    tmpdict['port'] = "80"
                else:
                    port = self._port_check(int(mem['port']))
                    tmpdict['port'] = str(port)
                pool_members.append(tmpdict)
            proxy_config_pool['members'] = pool_members
            proxy_config_pool[
                'name'] = f"/Common/ssloP_{self._values['name']}.app/ssloP_{self._values['name']}_proxyChainPool"

        if 'pool_name' in self._values['proxy_connect'] and self._values['proxy_connect']['pool_name'] is not None:
            proxy_config_pool['create'] = False
            proxy_config_pool['members'] = []
            proxy_config_pool['name'] = self._values['proxy_connect']['pool_name']

        proxy_config['pool'] = proxy_config_pool
        return proxy_config

    @property
    def pools(self):
        if self._values['proxy_connect'] is None:
            return {}
        pools = dict()
        pool_detail = dict()
        pool_detail['name'] = f"ssloP_{self._values['name']}_proxyChainPool"
        pool_detail['loadBalancingMode'] = 'predictive-node'
        pool_detail['monitors'] = {'names': ['/Common/gateway_icmp']}
        pool_detail['unhandledPool'] = True
        pool_detail['minActiveMembers'] = '0'
        pool_detail['callerContext'] = "policyConfigProcessor"

        if 'pool_members' in self._values['proxy_connect'] and \
                self._values['proxy_connect']['pool_members'] is not None:
            pool_members = list()
            for mem in self._values['proxy_connect']['pool_members']:
                tmpdict = dict()
                tmpdict['ip'] = mem['ip']
                if 'port' not in mem.keys() or not mem['port']:
                    tmpdict['port'] = "80"
                else:
                    port = self._port_check(int(mem['port']))
                    tmpdict['port'] = str(port)
                tmpdict['subPath'] = f"ssloP_{self._values['name']}.app"
                tmpdict['appService'] = f"ssloP_{self._values['name']}.app/ssloP_{self._values['name']}"
                pool_members.append(tmpdict)
            pool_detail['members'] = pool_members
            pools[f"ssloP_{self._values['name']}_proxyChainPool"] = pool_detail
            return pools
        return pools

    @property
    def policy_rules(self):
        if self._values['policy_rules'] is None:
            return []
        result = list()
        init_time = int(time.time())
        scenario = (self.policy_consumer, self.policy_provider)
        allowed_conditions = allowed_conditions_matrix.get(scenario, list(condition_type_list))
        allowed_actions = allowed_actions_matrix.get(
            scenario, ['allow', 'reject', 'abort', 'redirect']
        )
        allowed_ssl_for_allow = allowed_ssl_actions_matrix.get(scenario)
        default_action = 'reject' if 'reject' in allowed_actions else allowed_actions[0]
        for rule in self._values['policy_rules']:
            policy_rule = dict()
            policy_rule['index'] = init_time
            init_time = init_time + 10
            policy_rule['name'] = rule['name']
            policy_rule['operation'] = 'AND' if rule['match_type'] == 'match_all' else 'OR'
            policy_rule['mode'] = "edit"
            policy_rule['action'] = default_action
            if rule['policy_action'] is not None:
                policy_rule['action'] = rule['policy_action']
            if policy_rule['action'] not in allowed_actions:
                raise F5ModuleError(
                    f"For policy_consumer '{scenario[0]}' with policy_provider '{scenario[1]}', "
                    f"'policy_action' must be one of {allowed_actions}, "
                    f"but '{policy_rule['action']}' was entered."
                )
            condtns = rule.get('conditions') or []
            rule_condition_types = {c.get('condition_type') for c in condtns}
            # Conditions in http_phase_condition_types/l7_phase_condition_types put the rule in
            # the HTTP/L7 protocol phase respectively. Each phase restricts which of
            # ssl_action/service_chain are valid, independent of policy_action:
            #   HTTP phase: 'allow'/'reject'/'abort' -> neither field valid.
            #               'redirect' -> ssl_action fixed to 'intercept'; service_chain invalid.
            #   L7 phase:   'allow' -> ssl_action invalid; service_chain valid (optional).
            #               'reject'/'abort' -> neither field valid.
            #               'redirect' -> ssl_action fixed to 'intercept'; service_chain valid (optional).
            #   Any other phase: 'allow' -> ssl_action required; service_chain valid (optional).
            http_phase_hits = rule_condition_types & http_phase_condition_types
            l7_phase_hits = rule_condition_types & l7_phase_condition_types
            is_http_phase = bool(http_phase_hits)
            is_l7_phase = bool(l7_phase_hits)
            action_option = dict()
            action_option['ssl'] = ""
            action_option['serviceChain'] = ""
            action_option['urlRedirect'] = ""
            action = policy_rule['action']
            if action in ('allow', 'reject', 'abort'):
                if is_http_phase:
                    if rule['ssl_action'] is not None or rule['service_chain']:
                        raise F5ModuleError(
                            f"The {sorted(http_phase_hits)} condition(s) run in the HTTP protocol "
                            f"phase, so 'ssl_action' and 'service_chain' are invalid for '{action}' "
                            "rules that use them and must be omitted."
                        )
                elif is_l7_phase:
                    if rule['ssl_action'] is not None:
                        raise F5ModuleError(
                            f"The {sorted(l7_phase_hits)} condition(s) run in the L7 protocol "
                            f"phase, so 'ssl_action' is invalid for '{action}' rules that use "
                            "them and must be omitted."
                        )
                    if action != 'allow' and rule['service_chain']:
                        raise F5ModuleError(
                            f"The {sorted(l7_phase_hits)} condition(s) run in the L7 protocol "
                            f"phase, so 'service_chain' is invalid for '{action}' rules that use "
                            "them and must be omitted."
                        )
                    if action == 'allow':
                        action_option['serviceChain'] = self._prefixed_service_chain(rule['service_chain'])
                elif action == 'allow':
                    if rule['ssl_action'] is None:
                        raise F5ModuleError(
                            "'policy_action' is 'allow' but 'ssl_action' is required."
                        )
                    if allowed_ssl_for_allow is not None and rule['ssl_action'] not in allowed_ssl_for_allow:
                        allowed_display = sorted(
                            v for v in allowed_ssl_for_allow if v is not None
                        )
                        raise F5ModuleError(
                            f"For policy_consumer '{scenario[0]}' with policy_provider '{scenario[1]}', "
                            f"'ssl_action' for an 'allow' rule must be one of {allowed_display} "
                            f"but '{rule['ssl_action']}' was entered."
                        )
                    action_option['ssl'] = rule['ssl_action']
                    action_option['serviceChain'] = self._prefixed_service_chain(rule['service_chain'])
                # 'reject'/'abort' outside the HTTP/L7 phase: ssl_action/service_chain do not
                # apply; actionOptions stay blank as initialized above.
            if action == 'redirect':
                if Version(self._values['sslo_version']) < Version('11.1'):
                    raise F5ModuleError(
                        "The 'redirect' policy action is not supported on SSLO versions below 11.1. "
                        f"Detected version: {self._values['sslo_version']}"
                    )
                if not rule['redirect_url']:
                    raise F5ModuleError(
                        "The 'redirect' policy action requires a 'redirect_url' value."
                    )
                if not re.match(r'^https?://', rule['redirect_url']):
                    raise F5ModuleError(
                        "The 'redirect_url' must start with 'http://' or 'https://', "
                        f"but '{rule['redirect_url']}' was entered."
                    )
                action_option['ssl'] = 'intercept'
                if is_http_phase:
                    if rule['service_chain']:
                        raise F5ModuleError(
                            f"The {sorted(http_phase_hits)} condition(s) run in the HTTP protocol "
                            "phase, so 'service_chain' is invalid for 'redirect' rules that use "
                            "them and must be omitted."
                        )
                else:
                    action_option['serviceChain'] = self._prefixed_service_chain(rule['service_chain'])
                action_option['urlRedirect'] = rule['redirect_url']

            policy_rule['actionOptions'] = action_option

            policy_rule['conditions'] = condtns
            condition_result = list()
            condtype_list = list()
            for cond in condtns:
                if cond['condition_type'] is None:
                    raise F5ModuleError(
                        "condition_type must be specified for each policy condition"
                    )
                if cond['condition_type'] not in allowed_conditions:
                    raise F5ModuleError(
                        f"For policy_consumer '{scenario[0]}' with policy_provider '{scenario[1]}', "
                        f"condition_type '{cond['condition_type']}' is not supported. "
                        f"Allowed values: {allowed_conditions}"
                    )
                if cond['condition_type'] in category_list:
                    cla = dict()
                    cla['index'] = init_time
                    init_time = init_time + 10
                    cla['type'] = condition_type[cond['condition_type']]
                    for opt in cond['condition_option_category']:
                        if opt not in condition_category_list:
                            raise F5ModuleError(
                                f"condition_option_category '{opt}' must be one of : {condition_category_list}"
                            )
                    cla['options'] = {
                        "category": list(cond['condition_option_category'])
                    }
                    condition_result.append(cla)

                if cond['condition_type'] in port_list:
                    cla = dict()
                    cla['index'] = init_time
                    init_time = init_time + 10
                    cla['type'] = condition_type[cond['condition_type']]
                    if cond['condition_option_ports'] is not None:
                        cla['options'] = {
                            "port": list(cond['condition_option_ports'])
                        }
                        condition_result.append(cla)
                    elif cond['condition_option_portrange'] is not None:
                        cla['valueType'] = 'range'
                        cla['options'] = {
                            "port": [{
                                'valueType': 'range',
                                'portFrom': cond['condition_option_portrange']['port_from'],
                                'portTo': cond['condition_option_portrange']['port_to'],
                            }]
                        }
                        condition_result.append(cla)

                if cond['condition_type'] == "ssl_check":
                    cla = dict()
                    cla['index'] = init_time
                    init_time = init_time + 10
                    cla['type'] = condition_type[cond['condition_type']]
                    # r1 = list()
                    cla['options'] = {
                        "ssl": True
                    }
                    condition_result.append(cla)

                if cond['condition_type'] in subnet_list:
                    cla = dict()
                    cla['index'] = init_time
                    init_time = init_time + 10
                    cla['type'] = condition_type[cond['condition_type']]
                    if Version(self._values['sslo_version']) < Version('8.0'):
                        cla['options'] = {
                            "subnet": list(cond['condition_option_subnet'])
                        }
                    else:
                        cla['options'] = {
                            "subnet": [
                                {
                                    "valueType": 'datagroup' if re.match(
                                        r'^\/\w+\/[a-zA-Z0-9\-\.\_]+$', opt
                                    ) else 'staticValue',
                                    "subnet": opt,
                                }
                                for opt in cond['condition_option_subnet']
                            ]
                        }
                    condition_result.append(cla)

                if cond['condition_type'] in protocol_list:
                    cla = dict()
                    cla['index'] = init_time
                    init_time = init_time + 10
                    condtype_list.append(cond['condition_type'])
                    if 'tcp_l7_protocol_lookup' in condtype_list and 'udp_l7_protocol_lookup' in condtype_list:
                        raise F5ModuleError("condition_types :{0} cant be specified together in single rule".format(condtype_list))
                    cla['type'] = condition_type[cond['condition_type']]
                    r1 = list()
                    if cond['option_tcp_protocol'] is not None:
                        for opt in cond['option_tcp_protocol']:
                            if cond['condition_type'] == "tcp_l7_protocol_lookup":
                                if opt not in tcp_proto_list:
                                    raise F5ModuleError(
                                        "TCP L7 protocol must be one of: {0} , but {1} was entered.".format(tcp_proto_list, opt))
                                # 9.0 Update: only allow http2 if 9.0+
                                if Version(self._values['sslo_version']) < Version('9.0') and opt == 'http2':
                                    pass
                                else:
                                    r1.append(opt)
                                cla['options'] = {
                                    "protocol": r1
                                }
                    if cond['option_udp_protocol'] is not None:
                        for opt in cond['option_udp_protocol']:
                            if cond['condition_type'] == "udp_l7_protocol_lookup":
                                udp_proto_list = ["dns", "quic"]
                                if opt not in udp_proto_list:
                                    raise F5ModuleError(
                                        "UDP L7 protocol must be one of: {0} , but {1} was entered.".format(udp_proto_list, opt))
                                r1.append(opt)
                                cla['options'] = {
                                    "protocol": r1
                                }
                    condition_result.append(cla)

                if cond['condition_type'] in geolocation_list:
                    cla = dict()
                    cla['index'] = init_time
                    init_time = init_time + 10
                    cla['type'] = condition_type[cond['condition_type']]
                    r1 = list()
                    for opt in cond['geolocations']:
                        if "type" not in opt:
                            raise F5ModuleError(
                                "IP Geolocation requires at least one sub-item under the (geolocations) key that "
                                "contains a 'type' and 'value' sub-key.")
                        if "value" not in opt:
                            raise F5ModuleError(
                                "IP Geolocation requires at least one sub-item under the (geolocations) key that "
                                "contains a 'type' and 'value' sub-key.")

                        if opt["type"] not in {"countryCode", "countryName", "continent", "state"}:
                            raise F5ModuleError(
                                "IP Geolocation (type) must be one of 'countryCode', 'countryName', 'continent', "
                                "'state', but '" + opt["type"] + "' was entered.")
                        tmp = dict()
                        tmp['matchType'] = opt['type']
                        tmp['value'] = opt['value']
                        if re.match(r'^\/\w+\/[a-zA-Z0-9\-\.\_]+$', opt['value']):
                            tmp['valueType'] = "datagroup"
                        else:
                            tmp['valueType'] = "staticValue"
                        r1.append(tmp)
                    cla['options'] = {
                        "geolocations": r1
                    }
                    condition_result.append(cla)

                if cond['condition_type'] in reputation_list:
                    cla = dict()
                    cla['index'] = init_time
                    init_time = init_time + 10
                    cla['type'] = condition_type[cond['condition_type']]

                    reputation_allowed = ['good', 'bad', 'category']
                    opt = cond['condition_option_ip_reputation']
                    if opt not in reputation_allowed:
                        raise F5ModuleError(
                            "condition_option_ip_reputation must be one of: {0}, but '{1}' was entered.".format(
                                reputation_allowed, opt))
                    reputation_category_allowed = [
                        'Spam Sources', 'Windows Exploits', 'Web Attacks', 'Scanners', 'BotNets',
                        'Denial Of Service', 'Infected Sources', 'Phishing', 'Proxy',
                        'Cloud Providers', 'Mobile Threats', 'Tor Proxy'
                    ]
                    cat_list = []
                    if opt == 'category':
                        if not cond.get('condition_option_ip_reputation_category'):
                            raise F5ModuleError(
                                "condition_option_ip_reputation_category is required when "
                                "condition_option_ip_reputation is 'category'."
                            )
                        for cat in cond['condition_option_ip_reputation_category']:
                            if cat not in reputation_category_allowed:
                                raise F5ModuleError(
                                    "condition_option_ip_reputation_category entry '{0}' must be one of: {1}".format(
                                        cat, reputation_category_allowed))
                            cat_list.append(cat)
                    cla['options'] = {
                        "reputation": opt,
                        "category": cat_list
                    }
                    condition_result.append(cla)

                if cond['condition_type'] == 'client_vlan':
                    cla = dict()
                    cla['index'] = init_time
                    init_time = init_time + 10
                    cla['type'] = condition_type[cond['condition_type']]
                    cla['options'] = {
                        "vlans": list(cond['condition_option_vlan'])
                    }
                    condition_result.append(cla)

                if cond['condition_type'] == 'ip_protocol':
                    cla = dict()
                    cla['index'] = init_time
                    init_time = init_time + 10
                    cla['type'] = condition_type[cond['condition_type']]
                    opt = cond['condition_option_ip_protocol']
                    if opt not in ip_protocol_list:
                        raise F5ModuleError(
                            "ip_protocol must be one of: {0}, but '{1}' was entered.".format(
                                ip_protocol_list, opt))
                    cla['options'] = {
                        "ipProtocol": opt
                    }
                    condition_result.append(cla)

                if cond['condition_type'] in cert_list:
                    cla = dict()
                    cla['index'] = init_time
                    init_time = init_time + 10
                    cla['type'] = condition_type[cond['condition_type']]
                    cla['options'] = {
                        "value": self._build_match_pattern_list(
                            cond['condition_option_cert'], 'server_cert', check_datagroup=True
                        )
                    }
                    condition_result.append(cla)

                if cond['condition_type'] == 'server_name_tls_clienthello':
                    cla = dict()
                    cla['index'] = init_time
                    init_time = init_time + 10
                    cla['type'] = condition_type[cond['condition_type']]
                    cla['options'] = {
                        "value": self._build_match_pattern_list(
                            cond['condition_option_server_name'], 'server_name_tls_clienthello', check_datagroup=True
                        )
                    }
                    condition_result.append(cla)

                if cond['condition_type'] == 'url_match':
                    cla = dict()
                    cla['index'] = init_time
                    init_time = init_time + 10
                    cla['type'] = condition_type[cond['condition_type']]
                    cla['options'] = {
                        "url": self._build_match_pattern_list(
                            cond['condition_option_url'], 'url_match', check_datagroup=False
                        )
                    }
                    condition_result.append(cla)

            policy_rule['conditions'] = condition_result
            result.append(policy_rule)
        result = self._process_default_rule(result)
        return result

    def _process_default_rule(self, rules):
        if self.default_rule is None:
            return rules
        default_rule = dict()
        default_rule['name'] = 'All Traffic'
        default_rule['action'] = self.default_rule_allow_block if self.default_rule_allow_block else 'allow'
        default_rule['mode'] = 'edit'
        default_rule['actionOptions'] = {
            'ssl': self.default_rule_tls_intercept if self.default_rule_tls_intercept else 'bypass',
            'serviceChain': self.default_rule_service_chain if self.default_rule_service_chain else ''
        }
        default_rule['isDefault'] = True
        rules.append(default_rule)
        return rules

    @property
    def timeout(self):
        divisor = 10
        timeout = self._values['timeout']
        if timeout < 10 or timeout > 1800:
            raise F5ModuleError(
                "Timeout value must be between 10 and 1800 seconds."
            )
        if timeout > 99:
            divisor = 100
        delay = timeout / divisor

        return int(delay), divisor


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    pass


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1

    @staticmethod
    def _strip_rule_index(rules):
        stripped = []
        for rule in rules or []:
            r = {k: v for k, v in rule.items() if k != 'index'}
            if isinstance(r.get('conditions'), list):
                r['conditions'] = [
                    {k: v for k, v in c.items() if k != 'index'}
                    for c in r['conditions']
                ]
            stripped.append(r)
        return stripped

    @property
    def policy_rules(self):
        if (len(self.want.policy_rules) == 0) and (len(self.have.policy_rules) == 0):
            return None

        want_stripped = self._strip_rule_index(self.want.policy_rules)
        have_stripped = self._strip_rule_index(self.have.policy_rules)

        want_rules_list = [rule['name'] for rule in want_stripped]
        if "All Traffic" not in want_rules_list:
            have_cmp = [r for r in have_stripped if r.get('name') != 'All Traffic']
            diff = compare_complex_list(want_stripped, have_cmp)
        else:
            diff = compare_complex_list(want_stripped, have_stripped)
        if diff is None:
            return None

        l1 = sorted(have_stripped, key=lambda i: i['name'])
        l2 = sorted(diff, key=lambda i: i['name'])
        if l1 == l2:
            return None

        port1, port2 = [], []
        for rule in l1:
            if rule['name'] == 'All Traffic':
                continue
            for cond in rule.get('conditions', []):
                if cond.get('type') in port_map:
                    for port in cond['options']['port']:
                        if port.get('valueType') not in ('range', 'dataGroup'):
                            port1.append(port['port'])
        for rule in l2:
            if rule['name'] == 'All Traffic':
                continue
            for cond in rule.get('conditions', []):
                if cond.get('type') in port_map:
                    for port in cond['options']['port']:
                        port2.append(port)
        if port1 and port2 and port1 == port2:
            return None

        # Real difference — return the original (index-bearing) want so it
        # gets sent to SSLO as the update payload unchanged.
        return self.want.policy_rules

    @property
    def proxy_connect(self):
        if self.want.proxy_connect is None and self.have.proxy_connect:
            if self.have.proxy_connect.get('isProxyChainEnabled'):
                return {
                    'isProxyChainEnabled': False,
                    'username': '',
                    'password': '',
                    'pool': {'create': False, 'members': [{'ip': '', 'port': '3128'}], 'name': ''}
                }
        return compare_complex_list(self.want.proxy_connect, self.have.proxy_connect)

    @property
    def pools(self):
        return compare_complex_list(self.want.pools, self.have.pools)


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.module.params.update(dict(sslo_version=sslo_version(self.client)))
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()

        # define a set of common instance variables used during module execution
        self.block_id = None
        self.operation = None
        self.version = None
        self.json_dump = None

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def exec_module(self):
        changed = False
        result = dict()
        state = self.want.state

        check_sslo_provisioned(self.client)
        self.check_sslo_version()
        if state == 'present':
            changed = self.present()
        elif state == 'absent':
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        if self.json_dump:
            result.update(dict(json=self.json_dump))
        self._announce_deprecations(result)
        return result

    def check_sslo_version(self):
        self.version = sslo_version(self.client)
        if Version(self.version) > Version(max_sslo_version) or \
                Version(self.version) < Version(min_sslo_version):
            raise F5ModuleError(
                f"Unsupported SSL Orchestrator version, "
                f"requires a version between {min_sslo_version} and {max_sslo_version}"
            )
        return True

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.operation = 'CREATE'
        task_id, output = self.create_on_device()
        if task_id:
            self.wait_for_task(task_id)
        if output:
            self.json_dump = output
            return False
        return True

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            if self.want.dump_json:
                self.operation = 'MODIFY'
                unused_task_id, output = self.update_on_device()
                if output:
                    self.json_dump = output
            return False
        if self.module.check_mode:
            return True
        self.operation = 'MODIFY'
        task_id, output = self.update_on_device()
        if task_id:
            self.wait_for_task(task_id)
        if output:
            self.json_dump = output
            return False
        return True

    def remove(self):
        if self.module.check_mode:
            return True
        self.operation = 'DELETE'
        task_id, output = self.remove_from_device()
        if task_id:
            self.wait_for_task(task_id)
        if output:
            self.json_dump = output
            return False
        return True

    def add_create_values(self, params):
        if self.want.policy_consumer is None:
            params['policy_consumer'] = 'Outbound'
        if self.want.policy_provider is None:
            params['policy_provider'] = 'prp'
        if self.want.server_cert_check is None:
            params['server_cert_check'] = False
        if self.want.proxy_connect is None:
            params['proxy_connect'] = self.disable_proxy_connect()
        params = self.add_default_rule_values_for_create(params)
        return params

    def add_default_rule_values_for_create(self, params):
        """ adds default rule values during create operation if undefined by the user """
        if self.want.policy_rules is None:
            return params
        if any(r.get('name') == 'All Traffic' for r in params.get('policy_rules', [])):
            return params
        if self.want.default_rule is None:
            default_rule = dict()
            default_rule['name'] = 'All Traffic'
            default_rule['action'] = 'allow'
            default_rule['mode'] = 'edit'
            default_rule['actionOptions'] = {
                "ssl": 'bypass', "serviceChain": ''
            }
            default_rule['isDefault'] = True
            params['policy_rules'].append(default_rule)
            return params
        return params

    def add_sslo_9x_support(self, params):
        for rule in params['policy_rules']:
            if 'conditions' in rule:
                for conditn in rule['conditions']:
                    if conditn['type'] in port_map and 'valueType' not in conditn:
                        cla = dict()
                        cla["port"] = []
                        for port in conditn['options']['port']:
                            this_port = dict()
                            if re.match(r'^\/\w+\/[a-zA-Z0-9\-\.\_]+$', port):
                                this_port["port"] = port
                                this_port["valueType"] = "datagroup"
                            else:
                                this_port["port"] = port
                                this_port["valueType"] = "staticValue"
                                if port == "80":
                                    this_port["type"] = "HTTP"
                                elif port == "443":
                                    this_port["type"] = "HTTPS"
                                elif port == "21":
                                    this_port["type"] = "FTP"
                                elif port == "25":
                                    this_port["type"] = "SMTP"
                                else:
                                    this_port["type"] = "Others"
                            cla["port"].append(this_port)
                        conditn['options'] = cla
                        conditn["valueType"] = "valueAndDatagroup"
        return params

    def disable_proxy_connect(self):
        proxy_connect = dict()
        if self.want.proxy_connect is None:
            proxy_connect['isProxyChainEnabled'] = False
            proxy_connect['username'] = ''
            proxy_connect['password'] = ''
            proxy_connect['pool'] = {
                "create": False,
                "members": [
                    {
                        "ip": '',
                        "port": '3128'
                    }
                ],
                "name": ''
            }
            return proxy_connect
        return proxy_connect

    def add_missing_options(self, params):
        if self.changes.policy_consumer is None:
            params['policy_consumer'] = self.have.policy_consumer
        if self.changes.policy_provider is None:
            params['policy_provider'] = self.have.policy_provider or 'prp'
        if self.changes.proxy_connect is None:
            params['proxy_connect'] = self.have.proxy_connect
        if self.changes.policy_rules is None:
            params['policy_rules'] = self.have.policy_rules
        if self.changes.pools is None:
            params['pools'] = self.have.pools
        if self.changes.pools == {} and self.changes.proxy_connect is None:
            params['proxy_connect'] = self.disable_proxy_connect()
        if self.changes.server_cert_check is None:
            params['server_cert_check'] = self.have.server_cert_check
        params = self.add_default_rule_values_for_create(params)
        return params

    def add_json_metadata(self, payload=None):
        if not payload:
            payload = dict()
        payload['name'] = f"sslo_obj_SECURITY_POLICY_{self.operation}_{self.want.name}"
        payload['deployment_name'] = self.want.name
        payload['operation'] = self.operation
        payload['sslo_version'] = float(self.version)
        if self.operation == 'MODIFY' or self.operation == 'DELETE':
            payload['dep_ref'] = f"https://localhost/mgmt/shared/iapp/blocks/{self.block_id}"
            payload['block_id'] = self.block_id
        if self.operation == 'MODIFY':
            if self.have.to_net_id:
                payload['to_net_id'] = self.have.to_net_id
            if self.have.from_net_id:
                payload['from_net_id'] = self.have.from_net_id
        return payload

    def _get_policy_input_prop(self, output):
        for prop in output.get('inputProperties', []):
            if prop.get('id') == 'f5-ssl-orchestrator-policy':
                return prop['value']
        return None

    def _inject_restricted_properties(self, output, data):
        """Inject restrictedProperties for proxy chain password (SSLO >= 9.3)
        or obfuscate password (SSLO < 9.3)."""
        proxy = data.get('proxy_connect', {})
        if not proxy or not proxy.get('isProxyChainEnabled'):
            return
        policy_value = self._get_policy_input_prop(output)
        if policy_value is None:
            return
        if float(self.version) >= 9.3:
            if self.operation == 'CREATE':
                real_password = proxy.get('password', '')
                if real_password:
                    pf_id = generate_pfid('P_')
                    policy_value['proxyConfigurations']['password'] = pf_id
                    policy_value['proxyConfigurations']['pfId'] = pf_id
                    output['restrictedProperties'] = [
                        {'id': pf_id, 'type': 'STRING', 'value': real_password}
                    ]
            else:  # MODIFY
                have_proxy = self.have.proxy_connect or {}
                existing_pf_id = have_proxy.get('pfId')
                if existing_pf_id:
                    want_proxy = self.want.proxy_connect
                    update_password = (self.want._values.get('proxy_connect') or {}).get('update_password', False)
                    if want_proxy and want_proxy.get('password') and update_password:
                        rp_value = want_proxy['password']  # new plaintext — user explicitly set update_password: true
                    else:
                        rp_value = existing_pf_id  # sentinel — id == value, vault retains old password
                    policy_value['proxyConfigurations']['password'] = existing_pf_id
                    policy_value['proxyConfigurations']['pfId'] = existing_pf_id
                    output['restrictedProperties'] = [
                        {'id': existing_pf_id, 'type': 'STRING', 'value': rp_value}
                    ]
                else:
                    # Proxy being enabled for the first time on this block
                    want_proxy = self.want.proxy_connect
                    if want_proxy and want_proxy.get('password'):
                        real_password = want_proxy['password']
                        pf_id = generate_pfid('P_')
                        policy_value['proxyConfigurations']['password'] = pf_id
                        policy_value['proxyConfigurations']['pfId'] = pf_id
                        output['restrictedProperties'] = [
                            {'id': pf_id, 'type': 'STRING', 'value': real_password}
                        ]
        else:
            # SSLO < 9.3: store obfuscated password directly
            real_password = proxy.get('password', '')
            if real_password:
                policy_value['proxyConfigurations']['password'] = obfuscate(real_password)

    def exists(self):
        uri = "/mgmt/shared/iapp/blocks/"
        query = f"?$filter=name+eq+'{self.want.name}'"
        response = self.client.get(uri + query)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('items', None):
            if response['contents']['items'][0]['name'] == self.want.name:
                self.block_id = response['contents']['items'][0]['id']
                return True
        return False

    def create_on_device(self):
        payload = self.changes.to_return()
        data = self.add_create_values(self.add_json_metadata(payload))
        if Version(self.version) >= Version('9.0'):
            data = self.add_sslo_9x_support(data)
        output = process_json(data, create_modify)
        self._inject_restricted_properties(output, data)

        if self.want.dump_json:
            return None, output

        uri = "/mgmt/shared/iapp/blocks/"
        response = self.client.post(uri, data=output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = str(response['contents']['id'])
        return task_id, None

    def update_on_device(self):
        payload = self.changes.to_return()
        data = self.add_missing_options(self.add_json_metadata(payload))
        if Version(self.version) >= Version('9.0'):
            data = self.add_sslo_9x_support(data)
        output = process_json(data, create_modify)
        self._inject_restricted_properties(output, data)

        if self.want.dump_json:
            return None, output

        uri = "/mgmt/shared/iapp/blocks/"
        response = self.client.post(uri, data=output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = str(response['contents']['id'])
        return task_id, None

    def read_current_from_device(self):
        uri = "/mgmt/shared/iapp/blocks/"
        query = f"?$filter=name+eq+'{self.want.name}'"
        response = self.client.get(uri + query)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('items', None) and response['contents']['items'][0]['name'] == self.want.name:
            returned_json = response['contents']['items'][0]['inputProperties'][0]['value']
            self.block_id = response['contents']['items'][0]['id']
            return ApiParameters(params=returned_json)
        raise F5ModuleError(response['contents'])

    def delete_failed_operation_on_device(self, task):
        # use this method to delete the operation that failed
        # if there are any http errors we ignore them
        uri = "/mgmt/shared/iapp/blocks/{0}".format(task)
        response = self.client.delete(uri)

        if response['code'] in [200, 201, 202]:
            return True
        else:
            return False

    def wait_for_task(self, task_id):
        error = None
        delay, period = self.want.timeout
        for x in range(0, period):
            task = self._check_task_on_device(task_id)
            if task['state'] == 'BOUND':
                return True
            if task['state'] == 'ERROR':
                error = str(task['error'])
                break
            time.sleep(delay)
        if error:
            self.delete_failed_operation_on_device(task_id)
            raise F5ModuleError(f"{self.operation} operation error: {task_id} : {error}")
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def _check_task_on_device(self, task_id):
        uri = "/mgmt/shared/iapp/blocks/"
        query = f"?$filter=id+eq+'{task_id}'"
        response = self.client.get(uri + query)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['items'][0]

    def remove_from_device(self):
        data = self.add_json_metadata()
        output = process_json(data, delete)

        if self.want.dump_json:
            return None, output

        uri = "/mgmt/shared/iapp/blocks/"
        response = self.client.post(uri, data=output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = str(response['contents']['id'])
        return task_id, None


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(
                required=True,
            ),
            policy_consumer=dict(
                choices=['outbound', 'inbound'],
                default="outbound"
            ),
            policy_provider=dict(
                choices=['prp', 'ltm']
            ),
            default_rule=dict(
                type='dict',
                options=dict(
                    allow_block=dict(
                        choices=['allow', 'block']
                    ),
                    tls_intercept=dict(
                        choices=['bypass', 'intercept']
                    ),
                    service_chain=dict()
                )
            ),
            policy_rules=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(),
                    match_type=dict(
                        choices=['match_any', 'match_all']
                    ),
                    conditions=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            condition_type=dict(
                                choices=['category_lookup_all', 'category_lookup_sni', 'category_lookup_httpconnect',
                                         'ssl_check', 'client_port_match', 'server_port_match',
                                         'client_ip_subnet_match', 'server_ip_subnet_match', 'tcp_l7_protocol_lookup',
                                         'udp_l7_protocol_lookup', 'client_ip_geolocation', 'server_ip_geolocation',
                                         'client_ip_reputation', 'server_ip_reputation', 'client_vlan', 'ip_protocol',
                                         'server_cert_subject_dn', 'server_cert_issuer_dn', 'server_cert_subject_san',
                                         'server_name_tls_clienthello', 'url_match']
                            ),
                            condition_option_category=dict(
                                type='list',
                                elements='str'
                            ),
                            geolocations=dict(type='list', elements='dict'),
                            condition_option_ports=dict(type='list', elements='str'),
                            condition_option_portrange=dict(
                                type='dict',
                                options=dict(
                                    port_from=dict(),
                                    port_to=dict()
                                )
                            ),
                            condition_option_subnet=dict(type='list', elements='str'),
                            option_tcp_protocol=dict(type='list', elements='str'),
                            option_udp_protocol=dict(type='list', elements='str'),
                            condition_option_ip_reputation=dict(type='str', choices=['good', 'bad', 'category']),
                            condition_option_ip_reputation_category=dict(type='list', elements='str'),
                            condition_option_vlan=dict(type='list', elements='str'),
                            condition_option_ip_protocol=dict(type='str', choices=['tcp', 'udp']),
                            condition_option_cert=dict(type='list', elements='dict'),
                            condition_option_server_name=dict(type='list', elements='dict'),
                            condition_option_url=dict(type='list', elements='dict'),
                        ),
                        required_if=[
                            ('condition_type', 'client_port_match', ['condition_option_ports',
                                                                     'condition_option_portrange'], True),
                            ('condition_type', 'server_port_match', ['condition_option_ports',
                                                                     'condition_option_portrange'], True),
                            ('condition_type', 'category_lookup_all', ['condition_option_category'], True),
                            ('condition_type', 'category_lookup_sni', ['condition_option_category'], True),
                            ('condition_type', 'category_lookup_httpconnect', ['condition_option_category'], True),
                            ('condition_type', 'client_ip_subnet_match', ['condition_option_subnet'], True),
                            ('condition_type', 'server_ip_subnet_match', ['condition_option_subnet'], True),
                            ('condition_type', 'tcp_l7_protocol_lookup', ['option_tcp_protocol'], True),
                            ('condition_type', 'udp_l7_protocol_lookup', ['option_udp_protocol'], True),
                            ('condition_type', 'client_ip_geolocation', ['geolocations'], True),
                            ('condition_type', 'server_ip_geolocation', ['geolocations'], True),
                            ('condition_type', 'client_ip_reputation', ['condition_option_ip_reputation'], True),
                            ('condition_type', 'server_ip_reputation', ['condition_option_ip_reputation'], True),
                            ('condition_type', 'client_vlan', ['condition_option_vlan'], True),
                            ('condition_type', 'ip_protocol', ['condition_option_ip_protocol'], True),
                            ('condition_type', 'server_cert_subject_dn', ['condition_option_cert'], True),
                            ('condition_type', 'server_cert_issuer_dn', ['condition_option_cert'], True),
                            ('condition_type', 'server_cert_subject_san', ['condition_option_cert'], True),
                            ('condition_type', 'server_name_tls_clienthello', ['condition_option_server_name'], True),
                            ('condition_type', 'url_match', ['condition_option_url'], True)
                        ],
                        mutually_exclusive=[['condition_option_ports', 'condition_option_portrange'],
                                            ['option_tcp_protocol', 'option_udp_protocol']]

                    ),
                    policy_action=dict(
                        choices=['allow', 'reject', 'abort', 'redirect']
                    ),
                    ssl_action=dict(
                        choices=['bypass', 'intercept']
                    ),
                    service_chain=dict(),
                    redirect_url=dict(),
                ),
                required_if=[
                    ('policy_action', 'redirect', ('redirect_url',), True)]
            ),
            proxy_connect=dict(
                type='dict',
                options=dict(
                    pool_members=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            ip=dict(required=True),
                            port=dict(type='int')
                        )
                    ),
                    pool_name=dict(),
                    username=dict(),
                    password=dict(
                        no_log=True
                    ),
                    update_password=dict(
                        type='bool',
                        default=False
                    )
                ),
                mutually_exclusive=[
                    ['pool_members', 'pool_name']]
            ),
            server_cert_check=dict(type='bool'),
            timeout=dict(
                type='int',
                default=300
            ),
            state=dict(
                default='present',
                choices=['absent', 'present']
            ),
            dump_json=dict(
                type='bool',
                default='no'
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    if not HAS_NETADDR:
        module.fail_json(
            msg=missing_required_lib('netaddr'),
            exception=NETADDR_IMPORT_ERROR
        )

    if not HAS_PACKAGING:
        module.fail_json(
            msg=missing_required_lib('packaging'),
            exception=PACKAGING_IMPORT_ERROR
        )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
