# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ssl_key_cert import (
    ApiParameters, ModuleParameters, ModuleManager, ArgumentSpec
)
from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch
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
    def test_module_parameters_key(self):
        key_content = load_fixture('create_insecure_key1')
        args = dict(
            key_content=key_content,
            key_name="cert1",
            partition="Common",
            state="present",
        )
        p = ModuleParameters(params=args)
        assert p.key_name == 'cert1'
        assert p.key_filename == 'cert1.key'
        assert '-----BEGIN RSA PRIVATE KEY-----' in p.key_content
        assert '-----END RSA PRIVATE KEY-----' in p.key_content
        assert p.key_checksum == '91bdddcf0077e2bb2a0258aae2ae3117be392e83'
        assert p.state == 'present'

    def test_module_parameters_cert(self):
        cert_content = load_fixture('create_insecure_cert1')
        args = dict(
            cert_content=cert_content,
            cert_name="cert1",
            partition="Common",
            state="present",
        )
        p = ModuleParameters(params=args)
        assert p.cert_name == 'cert1'
        assert p.cert_filename == 'cert1.crt'
        assert 'Signature Algorithm' in p.cert_content
        assert '-----BEGIN CERTIFICATE-----' in p.cert_content
        assert '-----END CERTIFICATE-----' in p.cert_content
        assert p.cert_checksum == '1e55aa57ee166a380e756b5aa4a835c5849490fe'
        assert p.state == 'present'

    def test_module_issuer_cert_key(self):
        args = dict(
            issuer_cert='foo',
            partition="Common",
        )
        p = ModuleParameters(params=args)
        assert p.issuer_cert == '/Common/foo.crt'

    def test_api_issuer_cert_key(self):
        args = load_fixture('load_sys_file_ssl_cert_with_issuer_cert.json')
        p = ApiParameters(params=args)
        assert p.issuer_cert == '/Common/intermediate.crt'


class TestModuleManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ssl_key_cert.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_import_key_no_key_passphrase(self, *args):
        set_module_args(dict(
            key_name='foo',
            key_content=load_fixture('cert1'),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        cm = ModuleManager(module=module)
        cm.exists = Mock(side_effect=[False, True])
        cm.create_on_device = Mock(return_value=True)
        cm.remove_uploaded_file_from_device = Mock(return_value=True)

        results = cm.exec_module()

        assert results['changed'] is True
