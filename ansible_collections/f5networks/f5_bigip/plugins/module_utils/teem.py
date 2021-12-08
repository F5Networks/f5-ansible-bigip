# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import sys
import uuid
import re
import random
import socket

from time import time
from ssl import SSLError
from datetime import datetime

from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import (
    HTTPError, URLError
)

from .constants import (
    TEEM_ENDPOINT, TEEM_KEY, TEEM_TIMEOUT, TEEM_VERIFY, BASE_HEADERS, PLATFORM
)

from .version import CURRENT_COLL_VERSION


class TeemClient:
    def __init__(self, f5client, start_time):
        self.f5client = f5client
        self.start_time = start_time
        self.docker = False

    def prepare_request(self):
        self.docker = in_docker()
        dai = generate_asset_id(socket.gethostname())
        user_agent = 'F5_BIGIP/{0}'.format(CURRENT_COLL_VERSION)
        telemetry = self.build_telemetry()
        url = 'https://%s/ee/v1/telemetry' % TEEM_ENDPOINT
        headers = {
            'F5-ApiKey': TEEM_KEY,
            'F5-DigitalAssetId': str(dai),
            'F5-TraceId': str(uuid.uuid4()),
            'User-Agent': user_agent
        }
        headers.update(BASE_HEADERS)
        data = {
            'digitalAssetName': 'F5_BIGIP',
            'digitalAssetVersion': CURRENT_COLL_VERSION,
            'digitalAssetId': str(dai),
            'documentType': 'F5_BIGIP Ansible Collection',
            'documentVersion': '1',
            'observationStartTime': self.start_time,
            'observationEndTime': datetime.now().isoformat(),
            'epochTime': time(),
            'telemetryId': str(uuid.uuid4()),
            'telemetryRecords': telemetry
        }

        return url, headers, data

    def send(self):
        url, headers, data = self.prepare_request()
        payload = json.dumps(data)
        try:
            response = open_url(
                url=url,
                method='POST',
                headers=headers,
                timeout=TEEM_TIMEOUT,
                validate_certs=TEEM_VERIFY,
                data=payload
            )
        # we need to ensure that any connection errors to TEEM do not cause failure of module to run.
        except (HTTPError, URLError, SSLError):
            return None

        ok = re.search(r'20[01-4]', str(response.code))
        if ok:
            return True
        return False

    def build_telemetry(self):
        module_name = self.f5client.module_name
        tmp, version = self.f5client.platform
        platform = PLATFORM.get(tmp, '')
        ansible_version = self.f5client.ansible_version
        python_version = sys.version.split(' ', maxsplit=1)[0]

        return [{
            'CollectionName': 'F5_BIGIP',
            'CollectionVersion': CURRENT_COLL_VERSION,
            'CollectionModuleName': module_name,
            'f5Platform': platform,
            'f5SoftwareVersion': version,
            'ControllerAnsibleVersion': ansible_version,
            'ControllerPythonVersion': python_version,
            'ControllerAsDocker': self.docker
        }]


def generate_asset_id(seed):
    rd = random.Random()
    rd.seed(seed)
    result = uuid.UUID(int=rd.getrandbits(128))
    return result


def in_docker():
    """Check to see if we are running in a container

    Returns:
        bool: True if in a container. False otherwise.
    """
    try:
        with open('/proc/1/cgroup') as fh:
            lines = fh.readlines()
    except IOError:
        return False
    if any('/docker/' in x for x in lines):
        return True
    return False
