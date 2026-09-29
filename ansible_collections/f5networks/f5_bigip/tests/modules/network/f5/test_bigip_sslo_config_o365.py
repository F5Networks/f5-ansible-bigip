# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_o365 import (
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
    def test_module_parameters_basic(self):
        args = dict(
            endpoint='Worldwide',
            service_areas=dict(
                common=True,
                exchange=True,
                sharepoint=True,
                skype=False,
            ),
            outputs=dict(
                url_categories=True,
                url_datagroups=False,
                ip_datagroups=True,
            ),
            o365_categories=dict(
                all=True,
                optimize=True,
                default=True,
                allow=True,
            ),
            only_required=True,
            excluded_urls=['platform.linkedin.com', '.entrust.net'],
            excluded_ips=[],
            system=dict(
                log_level=1,
                ca_bundle='/Common/ca-bundle.crt',
                retry_attempts=3,
                retry_delay=300,
            ),
            schedule=dict(
                periods='daily',
                run_time='04:00',
            ),
            is_install=True,
            fetch_now=False,
            replicate_included_urls=False,
            timeout=300,
        )

        p = ModuleParameters(params=args)

        assert p.endpoint == 'Worldwide'
        assert p.service_areas == dict(common=True, exchange=True, sharepoint=True, skype=False)
        assert p.outputs == dict(url_categories=True, url_datagroups=False, ip_datagroups=True)
        assert p.o365_categories == dict(all=True, optimize=True, default=True, allow=True)
        assert p.only_required is True
        assert p.excluded_urls == ['platform.linkedin.com', '.entrust.net']
        assert p.excluded_ips == []
        assert p.system['ca_bundle'] == '/Common/ca-bundle.crt'
        assert p.system['log_level'] == 1
        assert p.system['retry_attempts'] == 3
        assert p.system['retry_delay'] == 300
        assert p.schedule['periods'] == 'daily'
        assert p.schedule['run_time'] == '04:00'
        assert p.is_install is True
        assert p.fetch_now is False
        assert p.replicate_included_urls is False

    def test_module_parameters_weekly_schedule(self):
        args = dict(
            endpoint='Worldwide',
            system=dict(ca_bundle='/Common/ca-bundle.crt'),
            schedule=dict(
                periods='weekly',
                run_time='02:00',
                run_date=3,
            ),
            timeout=300,
        )

        p = ModuleParameters(params=args)
        assert p.schedule['periods'] == 'weekly'
        assert p.schedule['run_date'] == 3
        assert p.schedule['run_time'] == '02:00'
        assert p.schedule['start_date'] == ''
        assert p.schedule['start_time'] == ''

    def test_module_parameters_monthly_schedule(self):
        args = dict(
            endpoint='Worldwide',
            system=dict(ca_bundle='/Common/ca-bundle.crt'),
            schedule=dict(
                periods='monthly',
                run_time='01:00',
                run_date=15,
            ),
            timeout=300,
        )

        p = ModuleParameters(params=args)
        assert p.schedule['periods'] == 'monthly'
        assert p.schedule['run_date'] == 15
        assert p.schedule['run_time'] == '01:00'

    def test_module_parameters_none_schedule(self):
        args = dict(
            endpoint='Worldwide',
            system=dict(ca_bundle='/Common/ca-bundle.crt'),
            schedule=dict(periods='none'),
            timeout=300,
        )

        p = ModuleParameters(params=args)
        assert p.schedule['periods'] == 'none'

    def test_module_parameters_included_urls(self):
        args = dict(
            endpoint='Worldwide',
            system=dict(ca_bundle='/Common/ca-bundle.crt'),
            included_urls=dict(
                all=['mycompany.com'],
                optimized=['mycompany.com'],
                default=['mycompany.com'],
                allow=['mycompany.com'],
            ),
            timeout=300,
        )

        p = ModuleParameters(params=args)
        assert p.included_urls == dict(
            all=['mycompany.com'],
            optimized=['mycompany.com'],
            default=['mycompany.com'],
            allow=['mycompany.com'],
        )

    def test_module_parameters_system_missing_ca_bundle_raises(self):
        args = dict(
            endpoint='Worldwide',
            system=dict(log_level=1),
            timeout=300,
        )

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as ctx:
            p.system  # noqa: F841
        assert "ca_bundle" in str(ctx.exception)

    def test_module_parameters_schedule_missing_run_time_raises(self):
        args = dict(
            endpoint='Worldwide',
            system=dict(ca_bundle='/Common/ca-bundle.crt'),
            schedule=dict(periods='daily'),
            timeout=300,
        )

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as ctx:
            p.schedule  # noqa: F841
        assert "run_time" in str(ctx.exception)

    def test_module_parameters_timeout_valid(self):
        args = dict(endpoint='Worldwide', timeout=600)
        p = ModuleParameters(params=args)
        delay, period = p.timeout
        assert delay == 6
        assert period == 100

    def test_module_parameters_timeout_invalid_raises(self):
        args = dict(endpoint='Worldwide', timeout=9999)
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as ctx:
            p.timeout  # noqa: F841
        assert "Timeout" in str(ctx.exception)

    def test_api_parameters(self):
        args = load_fixture('load_sslo_config_o365.json')
        p = ApiParameters(params=args)

        assert p.endpoint == 'Worldwide'
        assert p.service_areas == dict(common=True, exchange=True, sharepoint=True, skype=True)
        assert p.outputs == dict(url_categories=True, url_datagroups=False, ip_datagroups=True)
        assert p.only_required is True
        assert p.excluded_urls == ['platform.linkedin.com', '.entrust.net']
        assert p.excluded_ips == []
        assert p.system['ca_bundle'] == '/Common/ca-bundle.crt'
        assert p.schedule['periods'] == 'daily'
        assert p.status['description'] == 'URLs exists - update bypassed'
        assert p.device_status[0]['deviceId'] == 'bigip1'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch(
            'ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_o365.F5Client'
        )
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.p2 = patch(
            'ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_o365.sslo_version'
        )
        self.m2 = self.p2.start()
        self.m2.return_value = '9.0'
        self.p3 = patch(
            'ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_o365.check_sslo_provisioned'
        )
        self.m3 = self.p3.start()
        self.m3.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def _get_module(self):
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        return module

    def test_create_o365_config(self, *args):
        set_module_args(dict(
            endpoint='Worldwide',
            service_areas=dict(common=True, exchange=True, sharepoint=True, skype=True),
            outputs=dict(url_categories=True, url_datagroups=False, ip_datagroups=True),
            o365_categories=dict(all=True, optimize=True, default=True, allow=True),
            only_required=True,
            excluded_urls=['platform.linkedin.com', '.entrust.net'],
            excluded_ips=[],
            system=dict(log_level=1, ca_bundle='/Common/ca-bundle.crt', retry_attempts=3, retry_delay=300),
            schedule=dict(periods='daily', run_time='04:00'),
            state='present',
        ))

        module = self._get_module()
        mm = ModuleManager(module=module)

        # Config does not exist yet
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict()),                                     # exists() → False
            dict(code=200, contents=load_fixture('reply_sslo_config_o365_create.json')),  # _refresh_status
        ])
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        assert results['changed'] is True
        assert mm.client.post.called

    def test_create_o365_config_check_mode(self, *args):
        set_module_args(dict(
            endpoint='Worldwide',
            service_areas=dict(common=True, exchange=True, sharepoint=True, skype=True),
            outputs=dict(url_categories=True, url_datagroups=False, ip_datagroups=True),
            o365_categories=dict(all=True, optimize=True, default=True, allow=True),
            only_required=True,
            excluded_urls=[],
            excluded_ips=[],
            system=dict(ca_bundle='/Common/ca-bundle.crt'),
            schedule=dict(periods='daily', run_time='04:00'),
            _ansible_check_mode=True,
            state='present',
        ))

        module = self._get_module()
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        assert results['changed'] is True
        assert not mm.client.post.called

    def test_modify_o365_config(self, *args):
        set_module_args(dict(
            endpoint='Worldwide',
            service_areas=dict(common=True, exchange=True, sharepoint=True, skype=False),
            outputs=dict(url_categories=True, url_datagroups=True, ip_datagroups=True),
            o365_categories=dict(all=True, optimize=True, default=True, allow=True),
            only_required=False,
            excluded_urls=[],
            excluded_ips=['10.0.0.0/8'],
            system=dict(log_level=2, ca_bundle='/Common/ca-bundle.crt', retry_attempts=5, retry_delay=600),
            schedule=dict(periods='monthly', run_time='01:00', run_date=1),
            state='present',
        ))

        module = self._get_module()
        mm = ModuleManager(module=module)

        existing = load_fixture('load_sslo_config_o365.json')
        modified = load_fixture('reply_sslo_config_o365_modify.json')

        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=existing),   # exists() → True
            dict(code=200, contents=existing),   # read_current_from_device()
            dict(code=200, contents=modified),   # _refresh_status()
        ])
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        assert results['changed'] is True
        assert mm.client.post.called

    def test_no_change_o365_config(self, *args):
        existing = load_fixture('load_sslo_config_o365.json')

        set_module_args(dict(
            endpoint='Worldwide',
            service_areas=dict(common=True, exchange=True, sharepoint=True, skype=True),
            outputs=dict(url_categories=True, url_datagroups=False, ip_datagroups=True),
            o365_categories=dict(all=True, optimize=True, default=True, allow=True),
            only_required=True,
            excluded_urls=['platform.linkedin.com', '.entrust.net'],
            excluded_ips=[],
            system=dict(log_level=1, ca_bundle='/Common/ca-bundle.crt', retry_attempts=3, retry_delay=300),
            schedule=dict(periods='daily', run_time='04:00'),
            state='present',
        ))

        module = self._get_module()
        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=existing),   # exists() → True
            dict(code=200, contents=existing),   # read_current_from_device()
        ])

        results = mm.exec_module()

        assert results['changed'] is False
        assert not mm.client.post.called

    def test_status_always_returned(self, *args):
        existing = load_fixture('load_sslo_config_o365.json')

        set_module_args(dict(
            endpoint='Worldwide',
            service_areas=dict(common=True, exchange=True, sharepoint=True, skype=True),
            outputs=dict(url_categories=True, url_datagroups=False, ip_datagroups=True),
            o365_categories=dict(all=True, optimize=True, default=True, allow=True),
            only_required=True,
            excluded_urls=['platform.linkedin.com', '.entrust.net'],
            excluded_ips=[],
            system=dict(log_level=1, ca_bundle='/Common/ca-bundle.crt', retry_attempts=3, retry_delay=300),
            schedule=dict(periods='daily', run_time='04:00'),
            state='present',
        ))

        module = self._get_module()
        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=existing),
            dict(code=200, contents=existing),
        ])

        results = mm.exec_module()

        assert 'status' in results
        assert results['status']['description'] == 'URLs exists - update bypassed'
        assert 'device_status' in results
        assert results['device_status'][0]['deviceId'] == 'bigip1'

    def test_create_fails_on_post_error(self, *args):
        set_module_args(dict(
            endpoint='Worldwide',
            service_areas=dict(common=True, exchange=True, sharepoint=True, skype=True),
            outputs=dict(url_categories=True, url_datagroups=False, ip_datagroups=True),
            o365_categories=dict(all=True, optimize=True, default=True, allow=True),
            only_required=True,
            excluded_urls=[],
            excluded_ips=[],
            system=dict(ca_bundle='/Common/ca-bundle.crt'),
            schedule=dict(periods='daily', run_time='04:00'),
            state='present',
        ))

        module = self._get_module()
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=dict()))
        mm.client.post = Mock(return_value=dict(code=500, contents='Internal Server Error'))

        with self.assertRaises(F5ModuleError) as ctx:
            mm.exec_module()
        assert 'Failed to create' in str(ctx.exception)


if __name__ == '__main__':
    unittest.main()
