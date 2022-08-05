# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
import sys

from datetime import datetime
from unittest.mock import Mock, patch, mock_open
from unittest import TestCase

from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import connection_loader

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.client import F5Client
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.constants import TEEM_KEY
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.teem import (
    TeemClient, in_cicd, in_docker, generate_asset_id, determine_environment
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.version import CURRENT_COLL_VERSION
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


class FakeHTTPResponse:
    def __init__(self, value):
        self.value = value

    @property
    def code(self):
        return self.value


class TestTeemClient(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.f5_bigip.bigip"
        self.connection = connection_loader.get("httpapi", self.pc, "/dev/null")
        self.mock_send = Mock()
        self.connection.send = self.mock_send
        self.start_time = datetime.now().isoformat()
        self.fake_module = Mock()
        self.fake_module._name = 'fake_module'
        self.fake_module.ansible_version = '2.10'
        self.client = F5Client(client=self.connection.httpapi, module=self.fake_module)
        self.python_version = sys.version.split(' ', maxsplit=1)[0]

    @patch('ansible_collections.f5networks.f5_bigip.plugins.module_utils.teem.in_cicd', new_callable=Mock())
    def test_teem_client_build_telemetry_no_docker_no_cicd(self, m):
        m.return_value = (False, None)
        self.connection.send.return_value = connection_response(
            load_fixture('load_tmos_version.json')
        )

        teem = TeemClient(self.client, self.start_time)
        result = teem.build_telemetry()

        assert result[0]['CollectionName'] == 'F5_BIGIP'
        assert result[0]['CollectionVersion'] == CURRENT_COLL_VERSION
        assert result[0]['CollectionModuleName'] == 'fake_module'
        assert result[0]['f5Platform'] == 'BIG-IP'
        assert result[0]['f5SoftwareVersion'] == '15.1.0.1'
        assert result[0]['ControllerAnsibleVersion'] == '2.10'
        assert result[0]['ControllerPythonVersion'] == self.python_version
        assert result[0]['ControllerAsDocker'] is False
        assert result[0]['DockerHostname'] == 'none'
        assert result[0]['RunningInCiEnv'] is False
        assert result[0]['CiEnvName'] == 'none'

    @patch('ansible_collections.f5networks.f5_bigip.plugins.module_utils.teem.socket.gethostname', new_callable=Mock())
    @patch('ansible_collections.f5networks.f5_bigip.plugins.module_utils.teem.in_cicd', new_callable=Mock())
    def test_teem_client_build_telemetry_with_docker_in_cicd(self, m1, m2):
        m1.return_value = (True, 'FOO-CI/CD')
        m2.return_value = '8fc719d06c9e'
        self.fake_module._name = 'bigip_fake'
        self.connection.send.return_value = connection_response(
            load_fixture('load_tmos_version.json')
        )
        teem = TeemClient(self.client, self.start_time)
        with patch.object(teem, 'docker', True):
            result = teem.build_telemetry()

        assert result[0]['CollectionName'] == 'F5_BIGIP'
        assert result[0]['CollectionVersion'] == CURRENT_COLL_VERSION
        assert result[0]['CollectionModuleName'] == 'bigip_fake'
        assert result[0]['f5Platform'] == 'BIG-IP'
        assert result[0]['f5SoftwareVersion'] == '15.1.0.1'
        assert result[0]['ControllerAnsibleVersion'] == '2.10'
        assert result[0]['ControllerPythonVersion'] == self.python_version
        assert result[0]['ControllerAsDocker'] is True
        assert result[0]['DockerHostname'] == '8fc719d06c9e'
        assert result[0]['RunningInCiEnv'] is True
        assert result[0]['CiEnvName'] == 'FOO-CI/CD'

    @patch('ansible_collections.f5networks.f5_bigip.plugins.module_utils.teem.in_cicd', new_callable=Mock())
    def test_teem_client_build_telemetry_fq_name(self, m):
        m.return_value = (False, None)
        self.fake_module._name = 'f5networks.f5_bigip.bigip_fake'
        self.connection.send.return_value = connection_response(
            load_fixture('load_tmos_version.json')
        )

        teem = TeemClient(self.client, self.start_time)
        result = teem.build_telemetry()

        assert result[0]['CollectionName'] == 'F5_BIGIP'
        assert result[0]['CollectionVersion'] == CURRENT_COLL_VERSION
        assert result[0]['CollectionModuleName'] == 'bigip_fake'
        assert result[0]['f5Platform'] == 'BIG-IP'
        assert result[0]['f5SoftwareVersion'] == '15.1.0.1'
        assert result[0]['ControllerAnsibleVersion'] == '2.10'
        assert result[0]['ControllerPythonVersion'] == self.python_version
        assert result[0]['ControllerAsDocker'] is False
        assert result[0]['DockerHostname'] == 'none'
        assert result[0]['RunningInCiEnv'] is False
        assert result[0]['CiEnvName'] == 'none'

    def test_teem_client_prepare_request(self):
        self.connection.send.return_value = connection_response(
            load_fixture('load_tmos_version.json')
        )

        teem = TeemClient(self.client, self.start_time)
        url, headers, data = teem.prepare_request()

        assert url == 'https://product.apis.f5.com/ee/v1/telemetry'
        assert len(headers) == 5
        assert headers['User-Agent'] == 'F5_BIGIP/{0}'.format(CURRENT_COLL_VERSION)
        assert headers['F5-ApiKey'] == TEEM_KEY
        assert len(data) == 10
        assert data['digitalAssetVersion'] == CURRENT_COLL_VERSION
        assert data['observationStartTime'] == self.start_time

    @patch('ansible_collections.f5networks.f5_bigip.plugins.module_utils.teem.open_url')
    def test_teem_client_send(self, patched):
        self.connection.send.return_value = connection_response(
            load_fixture('load_tmos_version.json')
        )

        self.connection.httpapi._display_message = Mock()
        patched.return_value = FakeHTTPResponse(200)

        teem = TeemClient(self.client, self.start_time)
        teem.send()

        assert patched.call_args[1]['url'] == 'https://product.apis.f5.com/ee/v1/telemetry'
        assert patched.call_args[1]['headers']['User-Agent'] == 'F5_BIGIP/{0}'.format(CURRENT_COLL_VERSION)
        assert patched.call_args[1]['headers']['F5-ApiKey'] == TEEM_KEY
        assert CURRENT_COLL_VERSION in patched.call_args[1]['data']
        assert self.start_time in patched.call_args[1]['data']


class TestOtherFunctions(TestCase):
    def test_determine_environment_drone(self):
        def mock_os_env_return(value):
            if value == 'DRONE':
                return True
            return False

        with patch('ansible_collections.f5networks.f5_bigip.plugins.module_utils.teem.os.getenv') as env:
            env.side_effect = mock_os_env_return
            result = determine_environment()

        assert result == 'Drone CI'

    def test_determine_environment_codeship(self):
        def mock_os_env_return(value):
            if value == 'CI_NAME':
                return 'codeship'
            return False

        with patch('ansible_collections.f5networks.f5_bigip.plugins.module_utils.teem.os.getenv') as env:
            env.side_effect = mock_os_env_return
            result = determine_environment()

        assert result == 'CodeShip CI'

    def test_determine_environment_codeship_invalid_value(self):
        def mock_os_env_return(value):
            if value == 'CI_NAME':
                return 'otherci'
            return False

        with patch('ansible_collections.f5networks.f5_bigip.plugins.module_utils.teem.os.getenv') as env:
            env.side_effect = mock_os_env_return
            result = determine_environment()

        assert result is None

    @patch(
        'builtins.open', mock_open(
            read_data='14:name=systemd:/docker/8fc719d06c9e3\n13:rdma:/\n12:pids:/docker/8fc719d06c9e3\n'
        )
    )
    def test_in_docker_true(self):
        result = in_docker()

        assert result is True

    @patch('builtins.open', mock_open(read_data='14:name=systemd:/8fc719d06c9e3\n13:rdma:/\n'))
    def test_in_docker_false(self):
        result = in_docker()

        assert result is False

    @patch('builtins.open', new_callable=mock_open)
    def test_in_docker_except(self, mo):
        ioerror = mo.return_value
        ioerror.read.side_effect = IOError('[Errno 2] No such file or directory')
        result = in_docker()

        assert result is False

    def test_in_cicd_true(self):
        def mock_os_env_return(value):
            if value == 'TF_BUILD':
                return True
            return False

        with patch('ansible_collections.f5networks.f5_bigip.plugins.module_utils.teem.os.getenv') as env:
            env.side_effect = mock_os_env_return
            ok, env = in_cicd()

        assert ok is True
        assert env == 'Azure Pipelines'

    def test_in_cicd_false(self):
        def mock_os_env_return(value):
            return False

        with patch('ansible_collections.f5networks.f5_bigip.plugins.module_utils.teem.os.getenv') as env:
            env.side_effect = mock_os_env_return
            ok, env = in_cicd()

        assert ok is False
        assert env is None

    def test_generate_asset_id(self):
        fake_host = '8fc719d06c9e'
        result1 = generate_asset_id(fake_host)
        result2 = generate_asset_id(fake_host)
        result3 = generate_asset_id(fake_host)

        assert result1 == result2 == result3
