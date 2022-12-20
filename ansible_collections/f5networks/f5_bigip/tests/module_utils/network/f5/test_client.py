# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
from unittest.mock import Mock, patch, call
from unittest import TestCase

from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.six import StringIO
from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import connection_loader

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.constants import BASE_HEADERS
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.client import (
    F5Client, tmos_version, bigiq_version, module_provisioned, modules_provisioned, sslo_version,
    package_installed, packages_installed, send_teem, TransactionContextManager
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError
from ansible_collections.f5networks.f5_bigip.tests.utils.common import connection_response


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


class TestF5ClientBIGIP(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.f5_bigip.bigip"
        self.connection = connection_loader.get("httpapi", self.pc, "/dev/null")
        self.mock_send = Mock()
        self.connection.send = self.mock_send
        self.client = F5Client(client=self.connection.httpapi)

    def test_GET_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.get('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with('/testlink', None, method='GET', headers=expected_header)

    def test_GET_header_update_with_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )
        self.client.transact = 'tr1234567'
        self.client.get('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with('/testlink', None, method='GET', headers=expected_header)

    def test_GET_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.get('/testlink')
        self.connection.send.assert_called_once_with('/testlink', None, method='GET', headers=BASE_HEADERS)

    def test_GET_header_update_without_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )
        self.client.transact = 'tr1234567'
        self.client.get('/testlink')
        expected_header = {'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with('/testlink', None, method='GET', headers=expected_header)

    def test_POST_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.post('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='POST'
        )

    def test_POST_header_update_with_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}
        self.client.transact = 'tr1234567'
        self.client.post('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='POST'
        )

    def test_POST_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.post('/testlink', data=payload)
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=BASE_HEADERS, method='POST'
        )

    def test_POST_header_update_without_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}
        self.client.transact = 'tr1234567'

        self.client.post('/testlink', data=payload)
        expected_header = {'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='POST'
        )

    def test_PUT_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.put('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PUT'
        )

    def test_PUT_header_update_with_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}
        self.client.transact = 'tr1234567'
        self.client.put('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PUT'
        )

    def test_PUT_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.put('/testlink', data=payload)
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=BASE_HEADERS, method='PUT'
        )

    def test_PUT_header_update_without_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}
        self.client.transact = 'tr1234567'

        self.client.put('/testlink', data=payload)
        expected_header = {'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PUT'
        )

    def test_PATCH_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.patch('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PATCH'
        )

    def test_PATCH_header_update_with_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}
        self.client.transact = 'tr1234567'

        self.client.patch('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PATCH'
        )

    def test_PATCH_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.patch('/testlink', data=payload)
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=BASE_HEADERS, method='PATCH'
        )

    def test_PATCH_header_update_without_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}
        self.client.transact = 'tr1234567'
        self.client.patch('/testlink', data=payload)
        expected_header = {'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PATCH'
        )

    def test_DELETE_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.delete('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with('/testlink', None, method='DELETE', headers=expected_header)

    def test_DELETE_header_update_with_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )
        self.client.transact = 'tr1234567'
        self.client.delete('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with('/testlink', None, method='DELETE', headers=expected_header)

    def test_DELETE_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.delete('/testlink')
        self.connection.send.assert_called_once_with('/testlink', None, method='DELETE', headers=BASE_HEADERS)

    def test_DELETE_header_update_without_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )
        self.client.transact = 'tr1234567'
        self.client.delete('/testlink')
        expected_header = {'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with('/testlink', None, method='DELETE', headers=expected_header)

    def test_get_platform(self):
        self.connection.send.return_value = connection_response(
            load_fixture('load_tmos_version.json')
        )

        platform, version = self.client.platform
        assert platform == 'bigip'
        assert version == '15.1.0.1'


class TestF5ClientBIGIQ(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.f5_bigip.bigiq"
        self.connection = connection_loader.get("httpapi", self.pc, "/dev/null")
        self.mock_send = Mock()
        self.connection.send = self.mock_send
        self.client = F5Client(module=Mock(), client=self.connection.httpapi)

    def test_GET_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.get('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with('/testlink', None, method='GET', headers=expected_header)

    def test_GET_header_update_with_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )
        self.client.transact = 'tr1234567'
        self.client.get('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with('/testlink', None, method='GET', headers=expected_header)

    def test_GET_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.get('/testlink')
        self.connection.send.assert_called_once_with('/testlink', None, method='GET', headers=BASE_HEADERS)

    def test_GET_header_update_without_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )
        self.client.transact = 'tr1234567'
        self.client.get('/testlink')
        expected_header = {'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with('/testlink', None, method='GET', headers=expected_header)

    def test_POST_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.post('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='POST'
        )

    def test_POST_header_update_with_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}
        self.client.transact = 'tr1234567'

        self.client.post('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='POST'
        )

    def test_POST_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.post('/testlink', data=payload)
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=BASE_HEADERS, method='POST'
        )

    def test_POST_header_update_without_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}
        self.client.transact = 'tr1234567'

        self.client.post('/testlink', data=payload)
        expected_header = {'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='POST'
        )

    def test_PUT_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.put('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PUT'
        )

    def test_PUT_header_update_with_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}
        self.client.transact = 'tr1234567'

        self.client.put('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PUT'
        )

    def test_PUT_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.put('/testlink', data=payload)
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=BASE_HEADERS, method='PUT'
        )

    def test_PUT_header_update_without_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}
        self.client.transact = 'tr1234567'

        self.client.put('/testlink', data=payload)
        expected_header = {'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PUT'
        )

    def test_PATCH_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.patch('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PATCH'
        )

    def test_PATCH_header_update_with_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}
        self.client.transact = 'tr1234567'

        self.client.patch('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PATCH'
        )

    def test_PATCH_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.patch('/testlink', data=payload)
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=BASE_HEADERS, method='PATCH'
        )

    def test_PATCH_header_update_without_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}
        self.client.transact = 'tr1234567'

        self.client.patch('/testlink', data=payload)
        expected_header = {'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with(
            '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PATCH'
        )

    def test_DELETE_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.delete('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with('/testlink', None, method='DELETE', headers=expected_header)

    def test_DELETE_header_update_with_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )
        self.client.transact = 'tr1234567'
        self.client.delete('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with('/testlink', None, method='DELETE', headers=expected_header)

    def test_DELETE_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.delete('/testlink')
        self.connection.send.assert_called_once_with('/testlink', None, method='DELETE', headers=BASE_HEADERS)

    def test_DELETE_header_update_without_additional_headers_and_transaction(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )
        self.client.transact = 'tr1234567'
        self.client.delete('/testlink')
        expected_header = {'Content-Type': 'application/json',
                           'X-F5-REST-Coordination-Id': 'tr1234567'}
        self.connection.send.assert_called_once_with('/testlink', None, method='DELETE', headers=expected_header)

    def test_get_platform(self):
        self.connection.send.return_value = connection_response(
            load_fixture('load_bigiq_version.json')
        )

        platform, version = self.client.platform
        assert platform == 'bigiq'
        assert version == '7.1.0'


class TestTMOSVersion(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.f5_bigip.bigip"
        self.connection = connection_loader.get("httpapi", self.pc, "/dev/null")
        self.mock_send = Mock()
        self.connection.send = self.mock_send
        self.client = F5Client(client=self.connection.httpapi)

    def test_tmos_version_raises(self):
        self.connection.send.side_effect = HTTPError(
            'https://bigip.local/mgmt/tm/sys/', 400, '', {}, StringIO('{"errorMessage": "ERROR"}')
        )

        with self.assertRaises(F5ModuleError) as err:
            tmos_version(self.client)
        assert "{'errorMessage': 'ERROR'}" in str(err.exception)

    def test_tmos_version_returns(self):
        self.connection.send.return_value = connection_response(
            load_fixture('load_tmos_version.json')
        )
        version = tmos_version(self.client)
        self.connection.send.assert_called_once_with('/mgmt/tm/sys/', None, method='GET', headers=BASE_HEADERS)
        assert version == '15.1.0.1'

    def test_modules_provisioned_raises(self):
        self.connection.send.side_effect = HTTPError(
            'https://bigip.local/mgmt/tm/sys/provision', 400, '', {}, StringIO('{"errorMessage": "ERROR"}')
        )
        with self.assertRaises(F5ModuleError) as err:
            modules_provisioned(self.client)
        assert "{'errorMessage': 'ERROR'}" in str(err.exception)

    def test_modules_provisioned_returns_empty(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        modules = modules_provisioned(self.client)
        assert modules == []

    def test_modules_provisioned_returns(self):
        self.connection.send.return_value = connection_response(
            load_fixture('load_provisioned_modules.json')
        )
        modules = modules_provisioned(self.client)
        self.connection.send.assert_called_once_with(
            '/mgmt/tm/sys/provision', None, method='GET', headers=BASE_HEADERS
        )
        assert modules == ['ltm']

    def test_module_provisioned(self):
        self.connection.send.return_value = connection_response(
            load_fixture('load_provisioned_modules.json')
        )
        module1 = module_provisioned(self.client, 'afm')
        module2 = module_provisioned(self.client, 'ltm')

        self.connection.send.assert_any_call('/mgmt/tm/sys/provision', None, method='GET', headers=BASE_HEADERS)
        assert self.connection.send.call_count == 2
        assert module1 is False
        assert module2 is True


class TestBIGIQVersion(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.f5_bigip.bigiq"
        self.connection = connection_loader.get("httpapi", self.pc, "/dev/null")
        self.mock_send = Mock()
        self.connection.send = self.mock_send
        self.client = F5Client(client=self.connection.httpapi)

    def test_bigiq_version_raises_on_http_error(self):
        self.connection.send.side_effect = HTTPError(
            'https://bigiq.local/mgmt/shared/resolver/device-groups/cm-shared-all-big-iqs/devices',
            400, '', {}, StringIO('{"errorMessage": "ERROR"}')
        )
        with self.assertRaises(F5ModuleError) as err:
            bigiq_version(self.client)
        assert '{\'errorMessage\': \'ERROR\'}' in str(err.exception)

    def test_bigiq_version_raises_on_no_information(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )
        with self.assertRaises(F5ModuleError) as res:
            bigiq_version(self.client)
        assert 'Failed to retrieve BIG-IQ version information.' in str(res.exception)

    def test_bigiq_version_returns(self):
        self.connection.send.return_value = connection_response(
            load_fixture('load_bigiq_version.json')
        )
        version = bigiq_version(self.client)
        self.connection.send.assert_called_once_with(
            '/mgmt/shared/resolver/device-groups/cm-shared-all-big-iqs/devices?$select=version',
            None, method='GET', headers=BASE_HEADERS
        )
        assert version == '7.1.0'


class TestSsloVersion(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.f5_bigip.bigip"
        self.connection = connection_loader.get("httpapi", self.pc, "/dev/null")
        self.mock_send = Mock()
        self.connection.send = self.mock_send
        self.client = F5Client(client=self.connection.httpapi)

    def test_sslo_orchestrator_found(self):
        self.connection.send.return_value = connection_response(load_fixture('load_ilxpackages.json'))

        version = sslo_version(self.client)

        self.connection.send.assert_called_once_with(
            '/mgmt/shared/iapp/installed-packages', None, method='GET', headers=BASE_HEADERS
        )

        assert version == '8.0'

    def test_sslo_orchestrator_not_found_raises(self):
        self.connection.send.side_effect = HTTPError(
            'https://bigip.local/mgmt/shared/iapp/installed-packages', 404, '', {},
            StringIO('{"errorMessage": "not found"}')
        )
        with self.assertRaises(F5ModuleError) as err:
            sslo_version(self.client)

        assert 'SSL Orchestrator package does not appear to be installed. Aborting.' in str(err.exception)


class TestPackagesInstalled(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.f5_bigip.bigip"
        self.connection = connection_loader.get("httpapi", self.pc, "/dev/null")
        self.mock_send = Mock()
        self.connection.send = self.mock_send
        self.client = F5Client(client=self.connection.httpapi)

    def test_package_installed(self):
        self.connection.send.return_value = connection_response(load_fixture('load_global_packages.json'))

        installed = package_installed(self.client, 'fast')
        not_installed = package_installed(self.client, 'do')

        assert installed is True
        assert not_installed is False

    def test_packages_installed_empty(self):
        self.connection.send.side_effect = [
            HTTPError('/mgmt/shared/iapp/global-installed-packages', 404, '', {},
                      StringIO('{"errorMessage": "not found"}')),
            connection_response({'FOO': 'BAR', 'BAZ': 'FOO'})
        ]

        is_empty = packages_installed(self.client)

        assert is_empty == []

        is_empty = packages_installed(self.client)

        assert is_empty == []
        assert self.connection.send.call_count == 2

    def test_packages_installed_raises(self):
        self.connection.send.side_effect = HTTPError(
            '/mgmt/shared/iapp/global-installed-packages', 401, '', {}, StringIO('{"errorMessage": "invalid request"}')
        )

        with self.assertRaises(F5ModuleError) as err:
            packages_installed(self.client)

        assert "{'errorMessage': 'invalid request'}" in str(err.exception)


class TestTransactionContextManagerAndOtherFunctions(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.f5_bigip.bigip"
        self.connection = connection_loader.get("httpapi", self.pc, "/dev/null")
        self.mock_send = Mock()
        self.connection.send = self.mock_send
        self.client = F5Client(client=self.connection.httpapi)

    def test_transaction_context_manager_success(self):
        self.connection.send.side_effect = [
            connection_response({'transId': 'tr123456789'}),
            connection_response({'FOO': 'BAR', 'BAZ': 'FOO'}),
            connection_response('{}')
        ]

        with TransactionContextManager(self.client) as transact:
            transact.patch('/fake/api/url', data={'param1': 'value1'})
            assert self.client.transact == 'tr123456789'

        calls = [
            call('/mgmt/tm/transaction/', '{}', method='POST', headers={'Content-Type': 'application/json'}),
            call('/fake/api/url', '{"param1": "value1"}', method='PATCH',
                 headers={'X-F5-REST-Coordination-Id': 'tr123456789', 'Content-Type': 'application/json'}),
            call('/mgmt/tm/transaction/tr123456789', '{"state": "VALIDATING", "validateOnly": false}',
                 method='PATCH', headers={'Content-Type': 'application/json'})
        ]

        assert self.client.transact is None
        self.connection.send.assert_has_calls(calls, any_order=False)

    def test_transaction_context_manager_fails_at_start(self):
        self.connection.send.side_effect = HTTPError(
            '/mgmt/tm/transaction/', 401, '', {}, StringIO('{"errorMessage": "invalid request"}')
        )

        with self.assertRaises(F5ModuleError) as err:
            with TransactionContextManager(self.client) as transact:
                transact.patch('/fake/api/url', data={'param1': 'value1'})

        assert "{'errorMessage': 'invalid request'}" in str(err.exception)
        self.connection.send.assert_called_once_with(
            '/mgmt/tm/transaction/', '{}', method='POST', headers={'Content-Type': 'application/json'}
        )

    def test_transaction_context_manager_fails_at_exit(self):
        self.connection.send.side_effect = [
            connection_response({'transId': 'tr123456789'}),
            connection_response({'FOO': 'BAR', 'BAZ': 'FOO'}),
            HTTPError('/mgmt/tm/transaction/', 401, '', {}, StringIO('{"errorMessage": "failed at exit"}'))
        ]

        with self.assertRaises(F5ModuleError) as err:
            with TransactionContextManager(self.client) as transact:
                transact.patch('/fake/api/url', data={'param1': 'value1'})
                assert self.client.transact == 'tr123456789'

        assert "{'errorMessage': 'failed at exit'}" in str(err.exception)

        calls = [
            call('/mgmt/tm/transaction/', '{}', method='POST', headers={'Content-Type': 'application/json'}),
            call('/fake/api/url', '{"param1": "value1"}', method='PATCH',
                 headers={'X-F5-REST-Coordination-Id': 'tr123456789', 'Content-Type': 'application/json'}),
            call('/mgmt/tm/transaction/tr123456789', '{"state": "VALIDATING", "validateOnly": false}',
                 method='PATCH', headers={'Content-Type': 'application/json'})
        ]

        assert self.client.transact is None
        self.connection.send.assert_has_calls(calls, any_order=False)

    def test_send_teem(self):
        mock_response = Mock()
        self.connection.httpapi.get_option = mock_response
        self.connection.httpapi.get_option.side_effect = [True, False]

        with patch('ansible_collections.f5networks.f5_bigip.plugins.module_utils.client.TeemClient') as patched:
            send_teem(self.client, 12345)
            result = send_teem(self.client, 12345)

        patched.assert_called_once()
        patched.return_value.send.assert_called_once()
        assert result is False

    def test_ansible_version_module_name(self):
        fake_module = Mock()
        fake_module._name = 'fake_module'
        fake_module.ansible_version = '3.10'
        f5_client = F5Client(module=fake_module)

        assert f5_client.module_name == 'fake_module'
        assert f5_client.ansible_version == '3.10'
