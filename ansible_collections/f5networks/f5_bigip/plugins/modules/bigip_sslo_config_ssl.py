#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_sslo_config_ssl
short_description: Manage an SSL Orchestrator SSL configuration
description:
  - Manage an SSL Orchestrator SSL configuration.
version_added: "1.6.0"
options:
  name:
    description:
      - Specifies the name of the authentication object.
      - The configuration auto-prepends C(ssloT_) to the object.
      - Names should be less than 14 characters and not contain dashes C(-).
    type: str
    required: True
  client_settings:
    description:
      - Specifies the client-side SSL settings.
    type: dict
    suboptions:
      proxy_type:
        description:
          - Defines the type of proxy to configure.
          - This parameter is immutable after the object has been created.
          - This parameter is required when C(state) is C(present).
        type: str
        choices:
          - forward
          - reverse
      cipher_type:
        description:
          - Defines the type of cipher used.
        type: str
        choices:
          - string
          - group
      cipher_string:
        description:
          - Defines the string used for cipher strings.
          - This parameter is mutually exclusive with C(cipher_group).
          - This parameter is required when C(cipher_type) is C(string).
        type: str
      cipher_group:
        description:
          - Defines the existing cipher group.
          - This parameter is mutually exclusive with C(cipher_string).
          - This parameter is required when C(cipher_type) is C(group).
        type: str
      cert:
        description:
          - Defines the certificate applied in the client side settings.
          - This parameter is required together with C(key).
        type: str
      key:
        description:
          - Defines the private key applied in the client side settings.
          - This parameter is required together with C(cert).
        type: str
      chain:
        description:
          - Defines the certificate keychain in the client side settings.
        type: str
      ca_cert:
        description:
          - Defines the CA certificate applied in the client side settings.
          - This parameter is required when C(proxy_type) is C(forward), otherwise this setting
            is ignored.
          - This parameter is required together with C(ca_key).
        type: str
      ca_key:
        description:
          - Defines the CA private key applied in the client side settings.
          - This parameter is required when C(proxy_type) is C(forward), otherwise this setting
            is ignored.
          - This parameter is required together with C(ca_key).
        type: str
      ca_chain:
        description:
          - Defines the CA certificate keychain in the client side settings.
          - This parameter is required if C(proxy_type) is C(forward), otherwise this setting
            is ignored.
        type: str
      alpn:
        description:
          - "Enables or disables ALPN HTTP/2 full proxy."
          - This parameter can only be used when C(proxy_type) is C(forward).
          - This parameter is only available in SSLO version 9.0 and later.
        type: bool
      log_publisher:
        description:
          - Defines a specific log publisher to use for client-side SSL-related events.
          - This parameter is only available in SSLO version 9.0 and later.
        type: str
  server_settings:
    description:
      - Specifies the server-side SSL settings
    type: dict
    suboptions:
      cipher_type:
        description:
          - Defines the type of cipher used.
        type: str
        choices:
          - string
          - group
      cipher_string:
        description:
          - Defines the string used for cipher strings.
          - This parameter is mutually exclusive with C(cipher_group).
          - This parameter is required when C(cipher_type) is C(string).
        type: str
      cipher_group:
        description:
          - Defines the existing cipher group.
          - This parameter is mutually exclusive with C(cipher_string).
          - This parameter is required when C(cipher_type) is C(group).
        type: str
      ca_bundle:
        description:
          - Defines the certificate authority bundle used to validate remote server certificates.
          - This setting is most applicable in the forward proxy use case to validate remote server certificates.
        type: str
      block_expired:
        description:
          - Defines the action to take if an expired remote server certificate is encountered.
          - For reverse proxy, the default is to ignore expired certificates C(no).
          - For forward proxy, the default is to drop expired certificates C(yes).
        type: bool
      block_untrusted:
        description:
          - Defines the action to take if an untrusted remote server certificate is encountered,
            based on the defined C(ca_bundle).
          - For reverse proxy, the default is to ignore untrusted certificates C(no).
          - For forward proxy, the default is to drop untrusted certificates C(yes).
        type: bool
      ocsp:
        description:
          - Defines an OCSP configuration to use to perform certificate revocation checking
            against remote server certificates.
        type: str
      crl:
        description:
          - Defines a CRL configuration to use to perform certificate revocation checking
            against remote server certificates.
        type: str
      log_publisher:
        description:
          - Defines a specific log publisher to use for server-side SSL-related events.
          - This parameter is only available in SSLO version 9.0 and above.
        type: str
  bypass_handshake_failure:
    description:
      - Defines the action to take if a server side TLS handshake failure is detected.
      - A value of C(no) causes the connection to fail.
      - A value of C(no) shuts down TLS decryption and allows the connection to proceed un-decrypted.
    type: bool
  bypass_client_cert_failure:
    description:
      - Defines the action to take if a server side TLS handshake client certificate request is detected.
      - A value of C(no) causes the connection to fail.
      - A value of C(yes) shuts down TLS decryption and allows the connection to proceed un-decrypted.
    type: bool
  dump_json:
    description:
      - Sets the module to output a JSON blob for further consumption.
      - When C(yes), does not make any changes on the device and always returns C(changed=False).
      - The output provided is idempotent in nature, meaning if there are no changes to be made during
        C(MODIFY) on an existing service no JSON output is generated.
    type: bool
    default: no
  timeout:
    description:
      - The amount of time to wait for the C(CREATE), C(MODIFY) or C(DELETE) task to complete, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
  state:
    description:
      - When C(state) is C(present), ensures the object is created or modified.
      - When C(state) is C(absent), ensures the service is removed.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Wojciech Wypior (@wojtek0806)
  - Kevin Stewart (@kevingstewart)
'''

EXAMPLES = r'''
- hosts: all
  collections:
    - f5networks.f5_bigip
  connection: httpapi

  vars:
    ansible_host: "lb.mydomain.com"
    ansible_user: "admin"
    ansible_httpapi_password: "secret"
    ansible_network_os: f5networks.f5_bigip.bigip
    ansible_httpapi_use_ssl: yes

  tasks:
    - name: Create an SSLO SSL config with reverse proxy - output json only
      bigip_sslo_config_ssl:
        name: "reverse_foo"
        client_settings:
          proxy_type: "reverse"
          cert: "/Common/sslo_test.crt"
          key: "/Common/sslo_test.key"
        dump_json: yes

    - name: Create an SSLO SSL config with forward proxy
      bigip_sslo_config_ssl:
        name: "forward_foo"
        client_settings:
          proxy_type: "forward"
          cipher_type: "group"
          cipher_group: "/Common/f5-default"
          ca_cert: "/Common/default.crt"
          ca_key: "/Common/default.key"
          alpn: yes
        server_settings:
          cipher_type: "group"
          cipher_group: "/Common/f5-default"
        bypass_handshake_failure: yes
        timeout: 400

    - name: Modify an SSLO SSL config with forward proxy
      bigip_sslo_config_ssl:
        name: "forward_foo"
        client_settings:
          proxy_type: "forward"
          ca_cert: "/Common/sslo_test.crt"
          ca_key: "/Common/sslo_test.key"

    - name: Delete an SSLO SSL config
      bigip_sslo_config_ssl:
        name: "forward_foo"
        state: absent
'''

RETURN = r'''
client_settings:
  description: Client-side SSL settings.
  returned: changed
  type: complex
  contains:
    proxy_type:
       description: The type of proxy configured.
       type: str
       sample: forward
    cipher_type:
       description: The type of cipher used.
       type: str
       sample: string
    cipher_string:
       description: The string used for cipher strings.
       type: str
       sample: DEFAULT
    cipher_group:
       description: The existing cipher group.
       type: str
       sample: /Common/f5-default
    cert:
       description: The certificate applied in the client side settings.
       type: str
       sample: /Common/default.crt
    key:
       description: The private key applied in the client side settings.
       type: str
       sample: /Common/default.key
    chain:
       description: The certificate keychain in the client side settings.
       type: str
       sample: /Common/local-ca-chain.crt
    ca_cert:
       description: The CA certificate applied in the client side settings.
       type: str
       sample: /Common/default.crt
    ca_key:
       description: The CA private key applied in the client side settings.
       type: str
       sample: /Common/default.key
    ca_chain:
       description: The CA certificate keychain in the client side settings.
       type: str
       sample: /Common/local-ca-chain.crt
    alpn:
       description: "Enables or disables ALPN HTTP/2 full proxy."
       type: bool
       sample: True
    log_publisher:
       description: The log publisher used for client-side SSL-related events.
       type: str
       sample: /Common/sys-ssl-publisher
server_settings:
  description: Specifies the server-side SSL settings.
  returned: changed
  type: complex
  contains:
    cipher_type:
       description: The type of cipher used.
       type: str
       sample: string
    cipher_string:
       description: The string used for cipher strings.
       type: str
       sample: DEFAULT
    cipher_group:
       description: The existing cipher group
       type: str
       sample: /Common/f5-default
    ca_bundle:
       description: The certificate authority bundle used to validate remote server certificates
       type: str
       sample: /Common/ca-bundle.crt
    block_expired:
       description: The action to take if an expired remote server certificate is encountered.
       type: bool
       sample: True
    block_untrusted:
       description: The action to take if an untrusted remote server certificate is encountered.
       type: bool
       sample: True
    ocsp:
       description: Then existing OCSP configuration to validate revocation of remote server certificates.
       type: str
       sample: /Common/my-ocsp
    crl:
       description: The existing CRL configuration to validate revocation of remote server certificates.
       type: str
       sample: /Common/my-crl
    log_publisher:
       description: The log publisher used for server-side SSL-related events.
       type: str
       sample: /Common/sys-ssl-publisher
bypass_handshake_failure:
  description:
    - Defines the action to take if a server side TLS handshake failure is detected.
  returned: changed
  type: bool
  sample: True
bypass_client_cert_failure:
  description:
    - Defines the action to take if a server side TLS handshake client certificate request is detected.
  returned: changed
  type: bool
  sample: True
'''

import time
from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, sslo_version
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, process_json,
    flatten_boolean
)
from ..module_utils.constants import (
    min_sslo_version, max_sslo_version, json_enable_tls13
)

from ..module_utils.sslo_templates.sslo_ssl import (
    create_modify, delete
)


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []

    returnables = [
        'client_cipher_type',
        'client_cipher_string',
        'client_cipher_group',
        'client_cert',
        'client_key',
        'client_chain',
        'client_ca_cert',
        'client_ca_key',
        'client_ca_chain',
        'alpn',
        'client_log_publisher',
        'client_enable_tls13',
        'server_cipher_type',
        'server_cipher_string',
        'server_cipher_group',
        'server_ca_bundle',
        'block_expired',
        'block_untrusted',
        'server_ocsp',
        'server_crl',
        'server_log_publisher',
        'server_enable_tls13',
        'bypass_handshake_failure',
        'bypass_client_cert_failure',
        'proxy_type'
    ]

    updatables = [
        'client_cipher_type',
        'client_cipher_string',
        'client_cipher_group',
        'client_cert',
        'client_key',
        'client_chain',
        'client_ca_cert',
        'client_ca_key',
        'client_ca_chain',
        'alpn',
        'client_log_publisher',
        'client_enable_tls13',
        'server_cipher_type',
        'server_cipher_string',
        'server_cipher_group',
        'server_ca_bundle',
        'block_expired',
        'block_untrusted',
        'server_ocsp',
        'server_crl',
        'server_log_publisher',
        'server_enable_tls13',
        'bypass_handshake_failure',
        'bypass_client_cert_failure',
        'proxy_type'
    ]


class ApiParameters(Parameters):
    @property
    def proxy_type(self):
        if self.client_ca_cert is None:
            return 'reverse'
        return 'forward'

    @property
    def client_cipher_type(self):
        if self._values['clientSettings'] is None:
            return None
        cipher_type = self._values['clientSettings']['ciphers']['isCipherString']
        if cipher_type is True:
            return 'string'
        if cipher_type is False:
            return 'group'

    @property
    def client_cipher_string(self):
        if self._values['clientSettings'] is None:
            return None
        return self._values['clientSettings']['ciphers']['cipherString']

    @property
    def client_cipher_group(self):
        if self._values['clientSettings'] is None:
            return None
        return self._values['clientSettings']['ciphers']['cipherGroup']

    @property
    def client_cert(self):
        if self._values['clientSettings'] is None:
            return None
        if not self._values['clientSettings']['certKeyChain']:
            return None
        return self._values['clientSettings']['certKeyChain'][0]['cert']

    @property
    def client_key(self):
        if self._values['clientSettings'] is None:
            return None
        if not self._values['clientSettings']['certKeyChain']:
            return None
        return self._values['clientSettings']['certKeyChain'][0]['key']

    @property
    def client_chain(self):
        if self._values['clientSettings'] is None:
            return None
        if not self._values['clientSettings']['certKeyChain']:
            return None
        return self._values['clientSettings']['certKeyChain'][0]['chain']

    @property
    def client_ca_cert(self):
        if self._values['clientSettings'] is None:
            return None
        if not self._values['clientSettings']['caCertKeyChain']:
            return None
        return self._values['clientSettings']['caCertKeyChain'][0]['cert']

    @property
    def client_ca_key(self):
        if self._values['clientSettings'] is None:
            return None
        if not self._values['clientSettings']['caCertKeyChain']:
            return None
        return self._values['clientSettings']['caCertKeyChain'][0]['key']

    @property
    def client_ca_chain(self):
        if self._values['clientSettings'] is None:
            return None
        if not self._values['clientSettings']['caCertKeyChain']:
            return None
        return self._values['clientSettings']['caCertKeyChain'][0]['chain']

    @property
    def alpn(self):
        if self._values['clientSettings'] is None:
            return None
        return self._values['clientSettings'].get('alpn', None)

    @property
    def client_log_publisher(self):
        if self._values['clientSettings'] is None:
            return None
        return self._values['clientSettings'].get('logPublisher', None)

    @property
    def client_enable_tls13(self):
        if self._values['clientSettings'] is None:
            return None
        return self._values['clientSettings'].get('enabledSSLProcessingOptions', None)

    @property
    def server_cipher_type(self):
        if self._values['serverSettings'] is None:
            return None
        cipher_type = self._values['serverSettings']['ciphers']['isCipherString']
        if cipher_type is True:
            return 'string'
        if cipher_type is False:
            return 'group'

    @property
    def server_cipher_string(self):
        if self._values['serverSettings'] is None:
            return None
        return self._values['serverSettings']['ciphers']['cipherString']

    @property
    def server_cipher_group(self):
        if self._values['serverSettings'] is None:
            return None
        return self._values['serverSettings']['ciphers']['cipherGroup']

    @property
    def server_ca_bundle(self):
        if self._values['serverSettings'] is None:
            return None
        return self._values['serverSettings'].get('caBundle', None)

    @property
    def block_expired(self):
        if self._values['serverSettings'] is None:
            return None
        return self._values['serverSettings'].get('expiredCertificates', None)

    @property
    def block_untrusted(self):
        if self._values['serverSettings'] is None:
            return None
        return self._values['serverSettings'].get('untrustedCertificates', None)

    @property
    def server_ocsp(self):
        if self._values['serverSettings'] is None:
            return None
        return self._values['serverSettings'].get('ocsp', None)

    @property
    def server_crl(self):
        if self._values['serverSettings'] is None:
            return None
        return self._values['serverSettings'].get('crl', None)

    @property
    def server_log_publisher(self):
        if self._values['serverSettings'] is None:
            return None
        return self._values['serverSettings'].get('logPublisher', None)

    @property
    def server_enable_tls13(self):
        if self._values['serverSettings'] is None:
            return None
        return self._values['serverSettings'].get('enabledSSLProcessingOptions', None)

    @property
    def bypass_handshake_failure(self):
        return self._values['generalSettings']['bypassHandshakeAlert']

    @property
    def bypass_client_cert_failure(self):
        return self._values['generalSettings']['bypassClientCertFailure']


class ModuleParameters(Parameters):
    @property
    def name(self):
        name = self._values['name']
        if not name.startswith('ssloT_'):
            name = "ssloT_" + name
        return name

    @property
    def proxy_type(self):
        if self._values['client_settings'] is None:
            return None
        proxy = self._values['client_settings'].get('proxy_type', None)
        if proxy is None:
            raise F5ModuleError("The 'proxy_type' parameter is required when creating/modifying an SSL object.")
        return proxy

    @property
    def client_cipher_type(self):
        if self._values['client_settings'] is None:
            return None
        return self._values['client_settings'].get('cipher_type', None)

    @property
    def client_cipher_string(self):
        if self._values['client_settings'] is None:
            return None
        return self._values['client_settings'].get('cipher_string', None)

    @property
    def client_cipher_group(self):
        if self._values['client_settings'] is None:
            return None
        return self._values['client_settings'].get('cipher_group', None)

    @property
    def client_cert(self):
        if self._values['client_settings'] is None:
            return None
        return self._values['client_settings'].get('cert', None)

    @property
    def client_key(self):
        if self._values['client_settings'] is None:
            return None
        return self._values['client_settings'].get('key', None)

    @property
    def client_chain(self):
        if self._values['client_settings'] is None:
            return None
        return self._values['client_settings'].get('chain', None)

    @property
    def client_ca_cert(self):
        if self._values['client_settings'] is None:
            return None
        return self._values['client_settings'].get('ca_cert', None)

    @property
    def client_ca_key(self):
        if self._values['client_settings'] is None:
            return None
        return self._values['client_settings'].get('ca_key', None)

    @property
    def client_ca_chain(self):
        if self._values['client_settings'] is None:
            return None
        return self._values['client_settings'].get('ca_chain', None)

    @property
    def alpn(self):
        if self._values['client_settings'] is None:
            return None
        enable = flatten_boolean(self._values['client_settings'].get('alpn', None))
        if enable == 'yes':
            if self.proxy_type == 'reverse':
                raise F5ModuleError(
                    "The 'alpn' parameter can only be used with 'forward' proxy type."
                )
            return True
        if enable == 'no':
            return False

    @property
    def client_log_publisher(self):
        if self._values['client_settings'] is None:
            return None
        return self._values['client_settings'].get('log_publisher', None)

    @property
    def server_cipher_type(self):
        if self._values['server_settings'] is None:
            return None
        return self._values['server_settings'].get('cipher_type', None)

    @property
    def server_cipher_string(self):
        if self._values['server_settings'] is None:
            return None
        return self._values['server_settings'].get('cipher_string', None)

    @property
    def server_cipher_group(self):
        if self._values['server_settings'] is None:
            return None
        return self._values['server_settings'].get('cipher_group', None)

    @property
    def server_ca_bundle(self):
        if self._values['server_settings'] is None:
            return None
        return self._values['server_settings'].get('ca_bundle', None)

    @property
    def block_expired(self):
        if self._values['server_settings'] is None:
            return None
        enable = flatten_boolean(self._values['server_settings'].get('block_expired', None))
        if enable == 'yes':
            return True
        if enable == 'no':
            return False

    @property
    def block_untrusted(self):
        if self._values['server_settings'] is None:
            return None
        enable = flatten_boolean(self._values['server_settings'].get('block_untrusted', None))
        if enable == 'yes':
            return True
        if enable == 'no':
            return False

    @property
    def server_ocsp(self):
        if self._values['server_settings'] is None:
            return None
        return self._values['server_settings'].get('ocsp', None)

    @property
    def server_crl(self):
        if self._values['server_settings'] is None:
            return None
        return self._values['server_settings'].get('crl', None)

    @property
    def server_log_publisher(self):
        if self._values['server_settings'] is None:
            return None
        return self._values['server_settings'].get('log_publisher', None)

    @property
    def bypass_handshake_failure(self):
        enable = flatten_boolean(self._values['bypass_handshake_failure'])
        if enable == 'yes':
            return True
        if enable == 'no':
            return False

    @property
    def bypass_client_cert_failure(self):
        enable = flatten_boolean(self._values['bypass_client_cert_failure'])
        if enable == 'yes':
            return True
        if enable == 'no':
            return False

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


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    returnables = [
        'client_settings',
        'server_settings',
        'bypass_handshake_failure',
        'bypass_client_cert_failure',
    ]

    @property
    def client_settings(self):
        result = dict()
        if self.proxy_type:
            result['proxy_type'] = self.proxy_type
        if self.client_cipher_type:
            result['cipher_type'] = self.client_cipher_type
        if self.client_cipher_string:
            result['cipher_string'] = self.client_cipher_string
        if self.client_cipher_group:
            result['cipher_group'] = self.client_cipher_group
        if self.client_cert:
            result['cert'] = self.client_cert
        if self.client_key:
            result['key'] = self.client_key
        if self.client_chain:
            result['chain'] = self.client_chain
        if self.alpn:
            result['alpn'] = self.alpn
        if self.client_ca_cert:
            result['ca_cert'] = self.client_ca_cert
        if self.client_ca_key:
            result['ca_key'] = self.client_ca_key
        if self.client_ca_chain:
            result['ca_chain'] = self.client_ca_chain
        if self.client_log_publisher:
            result['log_publisher'] = self.client_log_publisher
        if result:
            return result

    @property
    def server_settings(self):
        result = dict()
        if self.server_cipher_type:
            result['cipher_type'] = self.server_cipher_type
        if self.server_cipher_string:
            result['cipher_string'] = self.server_cipher_string
        if self.server_cipher_group:
            result['cipher_group'] = self.server_cipher_group
        if self.server_ca_bundle:
            result['ca_bundle'] = self.server_ca_bundle
        if self.block_expired:
            result['block_expired'] = self.block_expired
        if self.block_untrusted:
            result['block_untrusted'] = self.block_untrusted
        if self.server_ocsp:
            result['ocsp'] = self.server_ocsp
        if self.server_crl:
            result['crl'] = self.server_crl
        if self.server_log_publisher:
            result['log_publisher'] = self.server_log_publisher
        if result:
            return result


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

    @property
    def proxy_type(self):
        if self.want.proxy_type != self.have.proxy_type:
            raise F5ModuleError("The 'proxy_type' parameter cannot be changed after SSL object has been created.")


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
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
                if isinstance(change, dict):
                    changed.update(change)
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
        if LooseVersion(self.version) > LooseVersion(max_sslo_version) or \
                LooseVersion(self.version) < LooseVersion(min_sslo_version):
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

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
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

    def add_json_metadata(self, payload=None):
        if not payload:
            payload = dict()
        payload['name'] = f"sslo_obj_SSL_SETTINGS_{self.operation}_{self.want.name}"
        payload['deployment_name'] = self.want.name
        payload['operation'] = self.operation
        payload['sslo_version'] = float(self.version)
        if self.operation == 'MODIFY' or self.operation == 'DELETE':
            payload['dep_ref'] = f"https://localhost/mgmt/shared/iapp/blocks/{self.block_id}"
            payload['block_id'] = self.block_id
        return payload

    def check_version_specific_parameters(self):
        if LooseVersion(self.version) < LooseVersion('9.0'):
            if self.changes.alpn is not None:
                raise F5ModuleError(
                    "The 'alpn' parameter is only available on SSLO version 9.0 and above."
                )
            if self.changes.client_log_publisher:
                raise F5ModuleError(
                    "The 'client_log_publisher' parameter is only available on SSLO version 9.0 and above."
                )
            if self.changes.server_log_publisher:
                raise F5ModuleError(
                    "The 'server_log_publisher' parameter is only available on SSLO version 9.0 and above."
                )

    def add_create_defaults(self, payload):
        if self.want.client_cert is None:
            payload['client_cert'] = '/Common/default.crt'
        if self.want.client_key is None:
            payload['client_key'] = '/Common/default.key'
        if self.want.client_cipher_type is None:
            payload['client_cipher_type'] = 'string'
        if self.want.client_cipher_string is None:
            payload['client_cipher_string'] = 'DEFAULT'
        if self.want.client_cipher_group is None:
            payload['client_cipher_group'] = '/Common/f5-default'
        if self.want.server_cipher_type is None:
            payload['server_cipher_type'] = 'string'
        if self.want.server_cipher_string is None:
            payload['server_cipher_string'] = 'DEFAULT'
        if self.want.server_cipher_group is None:
            payload['server_cipher_group'] = '/Common/f5-default'
        if self.want.server_ca_bundle is None:
            payload['server_ca_bundle'] = '/Common/ca-bundle.crt'
        if self.want.proxy_type == 'reverse':
            payload['block_untrusted'] = False
            payload['block_expired'] = False
        if self.want.proxy_type == 'forward':
            payload['block_untrusted'] = True
            payload['block_expired'] = True
        if self.want.bypass_handshake_failure is None:
            payload['bypass_handshake_failure'] = False
        if self.want.bypass_client_cert_failure is None:
            payload['bypass_client_cert_failure'] = False
        if LooseVersion(self.version) >= LooseVersion('9.0'):
            if self.want.client_log_publisher is None:
                payload['client_log_publisher'] = '/Common/sys-ssl-publisher'
            if self.want.server_log_publisher is None:
                payload['server_log_publisher'] = '/Common/sys-ssl-publisher'
        payload['client_enable_tls13'] = [json_enable_tls13]
        payload['server_enable_tls13'] = [json_enable_tls13]
        return payload

    def add_missing_options(self, payload):
        if self.changes.client_cert is None:
            payload['client_cert'] = self.have.client_cert
        if self.changes.client_key is None:
            payload['client_key'] = self.have.client_key
        if self.changes.client_chain is None and self.have.client_chain:
            payload['client_chain'] = self.have.client_chain
        if self.changes.client_ca_cert is None and self.want.proxy_type == 'forward' and self.have.client_ca_cert:
            payload['client_ca_cert'] = self.have.client_ca_cert
        if self.changes.client_ca_key is None and self.want.proxy_type == 'forward' and self.have.client_ca_key:
            payload['client_ca_key'] = self.have.client_ca_key
        if self.changes.client_ca_chain is None and self.want.proxy_type == 'forward' and self.have.client_ca_chain:
            payload['client_ca_chain'] = self.have.client_ca_chain
        if self.changes.client_cipher_type is None:
            payload['client_cipher_type'] = self.have.client_cipher_type
        if self.changes.client_cipher_string is None:
            payload['client_cipher_string'] = self.have.client_cipher_string
        if self.changes.client_cipher_group is None:
            payload['client_cipher_group'] = self.have.client_cipher_group
        if self.changes.client_log_publisher is None and self.have.client_log_publisher:
            payload['client_log_publisher'] = self.have.client_log_publisher
        if self.have.client_enable_tls13:
            payload['client_enable_tls13'] = self.have.client_enable_tls13
        if self.changes.server_cipher_type is None:
            payload['server_cipher_type'] = self.have.server_cipher_type
        if self.changes.server_cipher_string is None:
            payload['server_cipher_string'] = self.have.server_cipher_string
        if self.changes.server_cipher_group is None:
            payload['server_cipher_group'] = self.have.server_cipher_group
        if self.changes.server_ca_bundle is None:
            payload['server_ca_bundle'] = self.have.server_ca_bundle
        if self.changes.block_expired is None:
            payload['block_expired'] = self.have.block_expired
        if self.changes.block_untrusted is None:
            payload['block_untrusted'] = self.have.block_untrusted
        if self.changes.server_ocsp is None:
            payload['server_ocsp'] = self.have.server_ocsp
        if self.changes.server_crl is None:
            payload['server_crl'] = self.have.server_crl
        if self.changes.server_log_publisher is None and self.have.server_log_publisher:
            payload['server_log_publisher'] = self.have.server_log_publisher
        if self.have.server_enable_tls13:
            payload['server_enable_tls13'] = self.have.server_enable_tls13
        if self.changes.bypass_handshake_failure is None:
            payload['bypass_handshake_failure'] = self.have.bypass_handshake_failure
        if self.changes.bypass_client_cert_failure is None:
            payload['bypass_client_cert_failure'] = self.have.bypass_client_cert_failure
        if self.changes.alpn is None and self.have.alpn:
            payload['alpn'] = self.have.alpn
        payload['proxy_type'] = self.want.proxy_type
        return payload

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
        self.check_version_specific_parameters()
        data = self.add_create_defaults(self.add_json_metadata(payload))

        output = process_json(data, create_modify)

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
        self.check_version_specific_parameters()
        data = self.add_missing_options(self.add_json_metadata(payload))

        output = process_json(data, create_modify)

        if self.want.dump_json:
            return None, output

        uri = "/mgmt/shared/iapp/blocks/"
        response = self.client.post(uri, data=output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = str(response['contents']['id'])
        return task_id, None

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


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            client_settings=dict(
                type='dict',
                options=dict(
                    proxy_type=dict(
                        choices=['reverse', 'forward']
                    ),
                    cipher_type=dict(
                        choices=['string', 'group'],
                    ),
                    cipher_string=dict(),
                    cipher_group=dict(),
                    cert=dict(),
                    key=dict(no_log=True),
                    chain=dict(),
                    ca_cert=dict(),
                    ca_key=dict(no_log=True),
                    ca_chain=dict(),
                    alpn=dict(type='bool'),
                    log_publisher=dict(),
                ),
                mutually_exclusive=[
                    ['cipher_string', 'cipher_group'],
                ],
                required_if=[
                    ['cipher_type', 'string', ['cipher_string']],
                    ['cipher_type', 'group', ['cipher_group']],
                    ['proxy_type', 'forward', ['ca_cert']],
                ],
                required_together=[
                    ['ca_cert', 'ca_key'],
                    ['cert', 'key']
                ]
            ),
            server_settings=dict(
                type='dict',
                options=dict(
                    cipher_type=dict(
                        choices=['string', 'group'],
                    ),
                    cipher_string=dict(),
                    cipher_group=dict(),
                    ca_bundle=dict(),
                    block_expired=dict(type='bool'),
                    block_untrusted=dict(type='bool'),
                    ocsp=dict(),
                    crl=dict(),
                    log_publisher=dict(),
                ),
                mutually_exclusive=[
                    ['cipher_string', 'cipher_group']
                ],
                required_if=[
                    ['cipher_type', 'string', ['cipher_string']],
                    ['cipher_type', 'group', ['cipher_group']]
                ]
            ),
            bypass_handshake_failure=dict(type='bool'),
            bypass_client_cert_failure=dict(type='bool'),
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

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
