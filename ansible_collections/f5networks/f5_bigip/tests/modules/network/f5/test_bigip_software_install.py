# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json
import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("F5 Ansible modules require Python >= 2.7")

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_software_install import (
    ApiParameters, ModuleParameters, ModuleManager, ArgumentSpec
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
            volume='HD1.2',
            type='standard',
            image='BIGIP-13.0.0.0.0.1645.iso',
            timeout=600,
            volume_uri='/fake/foo/bar'
        )

        p = ModuleParameters(params=args)
        assert p.volume == 'HD1.2'
        assert p.image == 'BIGIP-13.0.0.0.0.1645.iso'
        assert p.timeout == (6.0, 100)
        assert p.volume_uri == '/fake/foo/bar'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_software_install.send_teem')
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_software_install.F5Client')
        self.p3 = patch('time.sleep')
        self.p3.start()
        self.m2 = self.p2.start()
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.m2.return_value = MagicMock()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_start_software_install(self, *args):
        set_module_args(dict(
            image='13.0.0.iso',
            volume='HD1.2',
        ))

        current = ApiParameters()
        current.read_image_from_device = Mock(
            side_effect=[
                ['13.0.0.iso'],
                ['BIGIP-12.1.3.4-0.0.2.iso'],
            ]
        )

        volumes = dict(code=200, contents=load_fixture('load_volumes.json'))
        volume = dict(code=404, contents=dict())
        images = dict(code=200, contents=load_fixture('load_software_image.json'))
        hotfixes = dict(code=404, contents=dict())

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.have = current
        mm.client.get = Mock(
            side_effect=[volumes, volume, volumes, volume, images, hotfixes]
        )
        mm.client.post = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['message'] == 'Started software image installation 13.0.0.iso on volume HD1.2.'
        assert results['volume_uri'] == '/mgmt/tm/sys/software/volume/HD1.2'

    def test_software_install_progress_check(self):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            state='installed',
            timeout=300,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        prog_27 = dict(code=200, contents=load_fixture('load_volume_install_27pct.json'))
        prog_75 = dict(code=200, contents=load_fixture('load_volume_install_75pct.json'))
        done = dict(code=200, contents=load_fixture('load_volume_install_complete.json'))

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.client.get = Mock(
            side_effect=[prog_27, prog_75, done]
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['message'] == 'Software installation on volume: HD1.2 complete.'

    def test_software_install_activation_progress_check(self):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        prog_27 = dict(code=200, contents=load_fixture('load_volume_install_27pct.json'))
        prog_75 = dict(code=200, contents=load_fixture('load_volume_install_75pct.json'))
        done = dict(code=200, contents=load_fixture('load_volume_install_active.json'))

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.client.get = Mock(
            side_effect=[prog_27, prog_75, done]
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['message'] == 'Software installation on volume: HD1.2 complete, volume: HD1.2 is now active.'

    def test_software_install_progress_check_device_not_ready(self):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(return_value=False)
        results = mm.exec_module()

        assert results['changed'] is False
        assert results['message'] == 'Device is restarting services, unable to check software installation status.'

    def test_software_install_progress_check_device_restarts(self):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        prog_27 = dict(code=200, contents=load_fixture('load_volume_install_27pct.json'))
        prog_75 = dict(code=200, contents=load_fixture('load_volume_install_75pct.json'))
        error = dict(code=400, contents=dict())

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(side_effect=[True, False])
        mm.client.get = Mock(
            side_effect=[prog_27, prog_75, error]
        )
        results = mm.exec_module()

        assert results['changed'] is False
        assert results['message'] == 'Device is restarting services, unable to check software installation status.'

    def test_software_install_fails(self):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        prog_27 = dict(code=200, contents=load_fixture('load_volume_install_27pct.json'))
        prog_75 = dict(code=200, contents=load_fixture('load_volume_install_75pct.json'))
        fail = dict(code=200, contents=load_fixture('load_volume_install_fail.json'))

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(return_value=True)
        mm.client.get = Mock(
            side_effect=[prog_27, prog_75, fail]
        )
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert "Software installation on volume: HD1.2 failed." in str(res.exception)

    def test_software_install_activation_fails(self):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        prog_27 = dict(code=200, contents=load_fixture('load_volume_install_27pct.json'))
        prog_75 = dict(code=200, contents=load_fixture('load_volume_install_75pct.json'))
        done = dict(code=200, contents=load_fixture('load_volume_install_complete.json'))

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(return_value=True)
        mm.client.get = Mock(
            side_effect=[prog_27, prog_75, done]
        )
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert "Software installation and activation of volume: HD1.2 failed." in str(res.exception)

    def test_software_install_progress_check_media_missing(self):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        resp = dict(code=200, contents=load_fixture('load_volume_install_media_missing.json'))
        error = dict(code=400, contents=dict())

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(side_effect=[True, False])
        mm.client.get = Mock(
            side_effect=[resp, error]
        )
        results = mm.exec_module()

        assert results['changed'] is False
        assert results['message'] == 'Device is restarting services, unable to check software installation status.'

    def test_software_install_progress_check_media_default(self):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        resp = dict(code=200, contents=load_fixture('load_volume_install_default.json'))
        error = dict(code=400, contents=dict())

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(side_effect=[True, False])
        mm.client.get = Mock(
            side_effect=[resp, error]
        )
        results = mm.exec_module()

        assert results['changed'] is False
        assert results['message'] == 'Device is restarting services, unable to check software installation status.'
