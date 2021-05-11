# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_fast_application import (
    Parameters, ArgumentSpec, ModuleManager
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
    def test_module_parameters(self):
        args = dict(
            content=dict(param1='foo', param2='bar'),
            tenant='test_tenant',
            application='test_app',
            template='example/foobar',
            timeout=600,
        )
        p = Parameters(params=args)
        assert p.tenant == 'test_tenant'
        assert p.application == 'test_app'
        assert p.template == 'example/foobar'
        assert p.content == dict(param1='foo', param2='bar')
        assert p.timeout == 600


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_fast_application.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_create_fast_application(self, *args):
        declaration = load_fixture('new_fast_app.json')
        set_module_args(dict(
            content=declaration,
            template='examples/simple_http',
            state='create',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.template_exists = Mock(return_value=True)
        mm.create_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert mm.want.timeout == (6, 100)
        assert results['changed'] is True
        assert results['template'] == 'examples/simple_http'
        assert results['content'] == declaration

    def test_update_fast_application(self, *args):
        declaration = load_fixture('fast_app_update.json')
        set_module_args(dict(
            content=declaration,
            tenant='sample_tenant',
            application='sample_app',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=True)
        mm.upsert_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert mm.want.timeout == (3, 100)
        assert results['changed'] is True
        assert results['tenant'] == 'sample_tenant'
        assert results['application'] == 'sample_app'
        assert results['content'] == declaration

    def test_remove_fast_application(self, *args):
        set_module_args(dict(
            tenant='sample_tenant',
            application='sample_app',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(side_effect=[True, False])
        mm.remove_from_device = Mock(return_value=True)

        results = mm.exec_module()

        assert mm.want.timeout == (3, 100)
        assert results['changed'] is True
        assert results['tenant'] == 'sample_tenant'
        assert results['application'] == 'sample_app'

    def test_purge_all_fast_applications(self, *args):
        set_module_args(dict(
            state='purge'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.purge_from_device = Mock(return_value=True)

        results = mm.exec_module()

        assert mm.want.timeout == (3, 100)
        assert results['changed'] is True
