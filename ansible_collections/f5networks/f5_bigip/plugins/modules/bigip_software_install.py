#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_software_install
short_description: Install software images on a BIG-IP
description:
  - Install new software images on a BIG-IP system.
version_added: "1.1.0"
options:
  image:
    description:
      - Image to install on the remote device.
    type: str
  block_device_image:
    description:
      - Image to install on the remote device. In the case of a VCMP guest,
        ensure this image is present on the VCMP host and is
        referenced from there, and not from the VCMP guest. An ISO image
        directly uploaded to the VCMP guest will not work.
    type: str
  volume:
    description:
      - The volume on which to install the software image.
    type: str
  state:
    description:
      - When C(installed), ensures the software is installed on the volume
        and the volume is set to be booted from. The device is B(not) rebooted
        into the new software.
      - When C(activated), performs the same operation as C(installed), but
        the system is rebooted to the new software.
    type: str
    choices:
      - activated
      - installed
    default: activated
  type:
    description:
      - The type of the BIG-IP.
      - Defaults to C(standard), the other choice is C(vcmp).
    type: str
    default: standard
    choices:
      - standard
      - vcmp
  volume_uri:
    description:
      - Target volume uri returned by installation task.
      - Used for checking status of software installation on the target volume.
    type: str
  timeout:
    description:
      - The amount of time in seconds to wait for software installation to finish.
      - The accepted value range is between C(150) and C(3600) seconds.
      - If the device needs to restart the module will return with no change and an appropriate message. In such case,
        it is up to the user to pause task execution until device is ready, see C(EXAMPLES) section.
    type: int
    default: 300
notes:
  - Checking for installation status with C(volume_uri) parameter is not idempotent, see C(EXAMPLES) section.
author:
  - Wojciech Wypior (@wojtek0806)
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
    - name: Ensure an existing image is activated in specified volume
      bigip_software_install:
        image: BIGIP-13.0.0.0.0.1645.iso
        volume: HD1.2
      register: task

    - name: Check for installation progress
      bigip_software_install:
        volume_uri: "{{task.volume_uri}}"
        timeout: 900
      register: result

    - name: Wait for 6 minutes if device is restarting services
      pause:
        minutes: 6
      when:
        - result.message == "Device is restarting services, unable to check software installation status."

    - name: Check for installation progress, after reboot
      bigip_software_install:
        volume_uri: "{{task.volume_uri}}"
        timeout: 900
      when:
        - result.message == "Device is restarting services, unable to check software installation status."

    - name: Ensure an existing image is activated in specified volume - Idempotent check
      bigip_software_install:
        image: BIGIP-13.0.0.0.0.1645.iso
        volume: HD1.2
      register: result

    - name: Assert Ensure an existing image is activated in specified volume - Idempotent check
      assert:
        that:
          - result is not changed
          - result is success
'''

RETURN = r'''
volume_uri:
  description: Target volume uri returned by installation task.
  returned: changed
  type: dict
  sample: hash/dictionary of values
message:
  description: Informative message of the ansible task status.
  returned: changed
  type: dict
  sample: hash/dictionary of values
'''

import time
from datetime import datetime

from ansible.module_utils.urls import urlparse
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import (
    Connection, ConnectionError
)

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name
)


class Parameters(AnsibleF5Parameters):
    api_map = {

    }

    api_attributes = [
        'options',
        'volume',
    ]

    returnables = [

    ]

    updatables = [

    ]


class ApiParameters(Parameters):
    @property
    def image_names(self):
        result = []
        result += self.read_image_from_device('image')
        result += self.read_image_from_device('hotfix')
        return result

    def read_image_from_device(self, t):
        uri = "/mgmt/tm/sys/software/{0}".format(t)
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            return []
        if 'items' not in response['contents']:
            return []
        return [x['name'].split('/')[0] for x in response['contents']['items']]

    @property
    def block_device_image_names(self):
        result = []
        result += self.read_block_device_image_from_device()
        result += self.read_block_device_hotfix_from_device()
        return result

    def read_block_device_image_from_device(self):
        uri = "/mgmt/tm/sys/software/block-device-image/"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            return []
        if 'items' not in response['contents']:
            return []
        return [x['name'] for x in response['contents']['items']]

    def read_block_device_hotfix_from_device(self):
        uri = "/mgmt/tm/sys/software/block-device-hotfix/"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            return []
        if 'items' not in response['contents']:
            return []
        return [x['name'] for x in response['contents']['items']]


class ModuleParameters(Parameters):
    @property
    def timeout(self):
        divisor = 100
        timeout = self._values['timeout']
        if timeout < 150 or timeout > 3600:
            raise F5ModuleError(
                "Timeout value must be between 150 and 3600 seconds."
            )

        delay = timeout / divisor

        return delay, divisor

    @property
    def version(self):
        if self._values['version']:
            return self._values['version']

        if self._values['type'] == "standard":
            self._values['version'] = self.image_info['version']
        elif self._values['type'] == "vcmp":
            self._values['version'] = self.block_device_image_info['version']
        return self._values['version']

    @property
    def build(self):
        # Return cached copy if we have it
        if self._values['build']:
            return self._values['build']

        # Otherwise, get copy from image info cache
        # self._values['build'] = self.image_info['build']

        if self._values['type'] == "standard":
            self._values['build'] = self.image_info['build']
        elif self._values['type'] == "vcmp":
            self._values['build'] = self.block_device_image_info['build']
        return self._values['build']

    @property
    def image_info(self):
        if self._values['image_info']:
            image = self._values['image_info']
        else:
            # Otherwise, get a new copy and store in cache
            image = self.read_image()
            self._values['image_info'] = image
        return image

    @property
    def block_device_image_info(self):
        if self._values['block_device_image_info']:
            block_device_image = self._values['block_device_image_info']
        else:
            # Otherwise, get a new copy and store in cache
            block_device_image = self.read_block_device_image()
            self._values['block_device_image_info'] = block_device_image
        return block_device_image

    @property
    def image_type(self):
        if self._values['image_type']:
            return self._values['image_type']
        if 'software:image' in self.image_info['kind']:
            self._values['image_type'] = 'image'
        else:
            self._values['image_type'] = 'hotfix'
        return self._values['image_type']

    @property
    def block_device_image_type(self):
        if self._values['block_device_image_type']:
            return self._values['block_device_image_type']
        if 'software:block-device-image' in self.block_device_image_info['kind']:
            self._values['block_device_image_type'] = 'block-device-image'
        else:
            self._values['block_device_image_type'] = 'block-device-hotfix'
        return self._values['block_device_image_type']

    def read_image(self):
        image = self.read_image_from_device(type='image')
        if image:
            return image
        image = self.read_image_from_device(type='hotfix')
        if image:
            return image
        return None

    def read_image_from_device(self, type):
        uri = "/mgmt/tm/sys/software/{0}/".format(type)
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            return None

        if 'items' in response['contents']:
            for item in response['contents']['items']:
                if item['name'].startswith(self.image):
                    return item

    def read_block_device_image(self):
        block_device_image = self.read_block_device_image_from_device()
        if block_device_image:
            return block_device_image
        block_device_image = self.read_block_device_hotfix_from_device()
        if block_device_image:
            return block_device_image
        return None

    def read_block_device_image_from_device(self):
        uri = "/mgmt/tm/sys/software/block-device-image/"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            return None

        if 'items' in response['contents']:
            for item in response['contents']['items']:
                if item['name'].startswith(self.block_device_image):
                    return item

    def read_block_device_hotfix_from_device(self):
        uri = "/mgmt/tm/sys/software/block-device-hotfix/"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            return None

        if 'items' in response['contents']:
            for item in response['contents']['items']:
                if item['name'].startswith(self.block_device_image):
                    return item


class Changes(Parameters):
    returnables = [
        'message',
        'volume_uri'
    ]

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


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(client=self.client, params=self.module.params)
        self.have = ApiParameters(client=self.client)
        self.changes = UsableChanges()
        self.volume_url = None

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

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def exec_module(self):
        start = datetime.now().isoformat()
        result = dict()

        if self.want.volume_uri:
            changed = self.check_progress()
        else:
            changed = self.present()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def present(self):
        if self.volume_exists():
            return False
        else:
            return self.update()

    def check_progress(self):
        if not self.device_is_ready():
            self.changes.update(
                {'message': 'Device is restarting services, unable to check software installation status.'}
            )
            return False
        return self.wait_for_software_install_on_device()

    def _set_volume_url(self, item):
        self.volume_url = urlparse(item['selfLink']).path

    def volume_exists(self):
        uri = "/mgmt/tm/sys/software/volume/"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        for item in response['contents']['items']:
            if item['name'].startswith(self.want.volume):
                self._set_volume_url(item)
                break

        if not self.volume_url:
            self.volume_url = uri + self.want.volume

        response = self.client.get(self.volume_url)

        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        # version key can be missing in the event that an existing volume has
        # no installed software in it.
        if self.want.version != response['contents'].get('version', None):
            return False
        if self.want.build != response['contents'].get('build', None):
            return False

        if self.want.state == 'installed':
            return True
        if self.want.state == 'activated':
            if 'defaultBootLocation' in response['contents']['media'][0]:
                return True
        return False

    def check_volume_status(self):
        try:
            response = self.client.get(self.want.volume_uri)
            return response['code'], response['contents']
        except ConnectionError:
            return 400, None

    def device_is_ready(self):
        uri = "/mgmt/tm/sys/available"
        try:
            response = self.client.get(uri)
            if response['code'] in [200, 201, 202]:
                return True
            return False
        except ConnectionError:
            return False

    def update(self):
        if self.module.check_mode:
            return True

        if self.want.type == "standard":
            if self.want.image and self.want.image not in self.have.image_names:
                raise F5ModuleError(
                    "The specified image was not found on the device."
                )
        elif self.want.type == "vcmp":
            if self.want.block_device_image and not any(
                have_block_device_image.startswith(self.want.block_device_image)
                    for have_block_device_image in self.have.block_device_image_names):
                raise F5ModuleError(
                    "The specified block_device_image was not found on the device."
                )

        options = list()
        if not self.volume_exists():
            options.append({'create-volume': True})
        if self.want.state == 'activated':
            options.append({'reboot': True})
        self.want.update({'options': options})
        self.update_on_device()
        return True

    def update_on_device(self):
        uri = None
        params = None
        if self.want.type == "standard":
            params = {
                "command": "install",
                "name": self.want.image,
            }
            params.update(self.want.api_params())
            uri = "/mgmt/tm/sys/software/{0}".format(self.want.image_type)
            self.changes.update({'message': 'Started software image installation {0} on volume {1}.'.format(
                self.want.image, self.want.volume)})
        elif self.want.type == "vcmp":
            params = {
                "command": "install",
                "name": transform_name(name=self.want.block_device_image),
            }
            params.update(self.want.api_params())
            uri = "/mgmt/tm/sys/software/{0}".format(transform_name(name=self.want.block_device_image_type))
            self.changes.update({'message': 'Started block software image installation {0} on volume {1}.'.format(
                self.want.block_device_image, self.want.volume)})

        response = self.client.post(uri, data=params)
        vol_uri = urlparse(self.volume_url).path
        self.changes.update({'volume_uri': '{0}'.format(vol_uri)})
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'commandResult' in response['contents'] and len(response['contents']['commandResult'].strip()) > 0:
            raise F5ModuleError(response['contents']['commandResult'])
        return True

    def wait_for_software_install_on_device(self):
        delay, period = self.want.timeout
        for x in range(0, period):
            code, response = self.check_volume_status()
            if code not in [200, 201, 202]:
                ready = self.device_is_ready()
                if not ready:
                    self.changes.update(
                        {'message': 'Device is restarting services, unable to check software installation status.'}
                    )
                    return False
                else:
                    code, response = self.check_volume_status()
            if code in [200, 201, 202]:
                if response['status'] == 'complete':
                    if self.want.state == 'activated':
                        if 'active' in response and response['active'] is True:
                            if 'media' in response:
                                if 'defaultBootLocation' in response['media'][0]:
                                    self.changes.update(
                                        {'message': 'Software installation on volume: {0} complete, '
                                                    'volume: {0} is now active.'.format(response['name'])
                                         }
                                    )
                                return True
                        if 'media' in response:
                            if 'defaultBootLocation' in response['media'][0]:
                                # We need to pause as volume might show  as default boot location but not active when
                                # the unit is in process of booting to volume, we pause to verify
                                # this is indeed happening
                                time.sleep(7)
                                if not self.device_is_ready():
                                    self.changes.update(
                                        {'message': 'Device is restarting services, '
                                                    'unable to check software installation status.'}
                                    )
                                    return False
                        if 'media' not in response:
                            # sometimes during volume boot process the api returns incomplete information,
                            # pausing to confirm reboot is happening
                            time.sleep(7)
                            if not self.device_is_ready():
                                self.changes.update(
                                    {'message': 'Device is restarting services, '
                                                'unable to check software installation status.'}
                                )
                                return False
                        raise F5ModuleError(
                            'Software installation and activation of volume: {0} failed.'.format(response['name'])
                        )
                    self.changes.update(
                        {'message': 'Software installation on volume: {0} complete.'.format(response['name'])}
                    )
                    return True
                elif response['status'] == 'failed':
                    raise F5ModuleError('Software installation on volume: {0} failed.'.format(response['name']))
            time.sleep(delay)
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            image=dict(),
            block_device_image=dict(),
            volume=dict(),
            state=dict(
                default='activated',
                choices=['activated', 'installed']
            ),
            type=dict(
                choices=['standard', 'vcmp'],
                default='standard'
            ),
            timeout=dict(
                type='int',
                default=300
            ),
            volume_uri=dict()
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
