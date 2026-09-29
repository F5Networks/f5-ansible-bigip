#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, F5 Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_sslo_config_o365
short_description: Manage the SSL Orchestrator O365 URL/Datagroup Updater configuration.
description:
  - Manages the F5 SSL Orch1.6.0estrator Office 365 URL and Datagroup Updater configuration.
  - Creates or updates the scheduled O365 URL update job on the BIG-IP device.
  - Uses the dedicated O365 worker endpoint, not the standard iApp blocks endpoint.
version_added: "1.6.0"
options:
  endpoint:
    description:
      - Specifies the Microsoft Office 365 endpoint type.
    type: str
    required: true
    choices:
      - Worldwide
      - USGovDoD
      - USGovGCCHigh
      - China
      - Germany
  service_areas:
    description:
      - Specifies which O365 service areas to include.
      - Each key maps to a service area. Set to C(true) to include, C(false) to exclude.
    type: dict
    suboptions:
      common:
        description: Include the Common service area.
        type: bool
        default: true
      exchange:
        description: Include the Exchange service area.
        type: bool
        default: true
      sharepoint:
        description: Include the SharePoint service area.
        type: bool
        default: true
      skype:
        description: Include the Skype service area.
        type: bool
        default: true
  outputs:
    description:
      - Specifies which output data types to generate.
    type: dict
    suboptions:
      url_categories:
        description: Generate URL category outputs.
        type: bool
        default: true
      url_datagroups:
        description: Generate URL datagroup outputs.
        type: bool
        default: false
      ip_datagroups:
        description: Generate IP datagroup outputs.
        type: bool
        default: true
  o365_categories:
    description:
      - Specifies which O365 URL categories to create/update.
    type: dict
    suboptions:
      all:
        description: Include the All category.
        type: bool
        default: true
      optimize:
        description: Include the Optimize category.
        type: bool
        default: true
      default:
        description: Include the Default category.
        type: bool
        default: true
      allow:
        description: Include the Allow category.
        type: bool
        default: true
  only_required:
    description:
      - When C(true), only required O365 URLs are included.
    type: bool
    default: true
  excluded_urls:
    description:
      - List of URLs to exclude from O365 URL updates.
      - If not provided, defaults to an empty list.
    type: list
    elements: str
    default: []
  included_urls:
    description:
      - Specifies additional URLs to include, organized by O365 category.
    type: dict
    suboptions:
      all:
        description: Additional URLs included in the All category.
        type: list
        elements: str
      optimized:
        description: Additional URLs included in the Optimize category.
        type: list
        elements: str
      default:
        description: Additional URLs included in the Default category.
        type: list
        elements: str
      allow:
        description: Additional URLs included in the Allow category.
        type: list
        elements: str
  excluded_ips:
    description:
      - List of IP addresses/subnets to exclude from O365 IP updates.
      - If not provided, defaults to an empty list.
    type: list
    elements: str
    default: []
  system:
    description:
      - Specifies system-level configuration for the O365 updater.
    type: dict
    suboptions:
      log_level:
        description: Log verbosity level.
        type: int
        default: 1
      ca_bundle:
        description:
          - Path to the CA certificate bundle on the BIG-IP device.
          - This parameter is required when C(system) is specified.
        type: str
        required: true
      working_directory:
        description: Working directory for the O365 updater script.
        type: str
        default: /var/config/rest/iapps/f5-iappslx-ssl-orchestrator/nodejs/o365
      retry_attempts:
        description: Number of retry attempts on failure.
        type: int
        default: 3
      retry_delay:
        description: Delay in seconds between retry attempts.
        type: int
        default: 300
  schedule:
    description:
      - Specifies the update schedule for the O365 URL updater.
    type: dict
    suboptions:
      periods:
        description:
          - Frequency of the scheduled update.
          - Use C(none) to disable scheduled updates.
        type: str
        required: true
        choices:
          - none
          - daily
          - weekly
          - monthly
      run_time:
        description:
          - Time of day to run the update, in C(HH:MM) 24-hour format.
          - Required when C(periods) is C(daily), C(weekly), or C(monthly).
        type: str
      run_date:
        description:
          - For C(weekly) schedules, specifies the day of the week as an integer
            where C(1=Monday) and C(7=Sunday).
          - For C(monthly) schedules, specifies the day of the month (1-31).
          - Not used when C(periods) is C(daily) or C(none).
        type: int
      start_date:
        description:
          - Optional start date for the schedule. Defaults to empty string if not provided.
        type: str
        default: ''
      start_time:
        description:
          - Optional start time for the schedule. Defaults to empty string if not provided.
        type: str
        default: ''
  is_install:
    description:
      - When C(true), installs/saves the O365 configuration on the device.
    type: bool
    default: true
  fetch_now:
    description:
      - When C(true), triggers an immediate O365 URL fetch after saving the configuration.
    type: bool
    default: false
  replicate_included_urls:
    description:
      - When C(true), replicates the C(included_urls) list across all selected
        C(o365_categories) entries so the O365 script generates http/https URLs for each.
      - Set to C(true) when C(o365_categories) or C(included_urls) have changed.
    type: bool
    default: false
  timeout:
    description:
      - The amount of time to wait for the task to complete, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
  state:
    description:
      - When C(present), ensures the O365 updater configuration is created or updated.
    type: str
    choices:
      - present
    default: present
notes:
  - This module uses the dedicated O365 worker endpoint, not the standard SSLo iApp blocks endpoint.
  - "Deleting the O365 configuration is not supported via the API. Use C(state=present) only."
  - Tested on BIG-IP 17.1 with SSLo 11.x.
author:
  - Atul Prasad (@aprasad)
  - Shweta Bakliwal (@sbakliwal)
'''

EXAMPLES = r'''
- name: Create O365 URL/Datagroup Updater with daily schedule
  f5networks.f5_bigip.bigip_sslo_config_o365:
    endpoint: Worldwide
    service_areas:
      common: true
      exchange: true
      sharepoint: true
      skype: false
    outputs:
      url_categories: true
      url_datagroups: false
      ip_datagroups: true
    o365_categories:
      all: true
      optimize: true
      default: true
      allow: true
    only_required: true
    excluded_urls:
      - "platform.linkedin.com"
      - ".entrust.net"
    excluded_ips:
      - "10.0.0.0/8"
    included_urls:
      all:
        - "mysite.com"
      optimized:
        - "mysite.com"
      default:
        - "mysite.com"
      allow:
        - "mysite.com"
    system:
      log_level: 1
      ca_bundle: "/Common/ca-bundle.crt"
      retry_attempts: 3
      retry_delay: 300
    schedule:
      periods: daily
      run_time: "04:00"
    state: present

- name: Update O365 updater to weekly schedule on Wednesday
  f5networks.f5_bigip.bigip_sslo_config_o365:
    endpoint: Worldwide
    service_areas:
      common: true
      exchange: true
      sharepoint: true
      skype: true
    outputs:
      url_categories: true
      url_datagroups: false
      ip_datagroups: true
    o365_categories:
      all: true
      optimize: true
      default: true
      allow: true
    only_required: true
    excluded_urls: []
    excluded_ips: []
    system:
      ca_bundle: "/Common/ca-bundle.crt"
    schedule:
      periods: weekly
      run_time: "02:00"
      run_date: 3
    replicate_included_urls: true
    state: present

- name: Disable O365 scheduled updates
  f5networks.f5_bigip.bigip_sslo_config_o365:
    endpoint: Worldwide
    service_areas:
      common: true
      exchange: true
      sharepoint: true
      skype: true
    outputs:
      url_categories: true
      url_datagroups: false
      ip_datagroups: true
    o365_categories:
      all: true
      optimize: true
      default: true
      allow: true
    only_required: true
    excluded_urls: []
    excluded_ips: []
    system:
      ca_bundle: "/Common/ca-bundle.crt"
    schedule:
      periods: none
    state: present
'''

RETURN = r'''
endpoint:
  description: The configured O365 endpoint type.
  returned: changed
  type: str
  sample: Worldwide
service_areas:
  description: The configured O365 service areas.
  returned: changed
  type: dict
  sample:
    common: true
    exchange: true
    sharepoint: true
    skype: false
outputs:
  description: The configured output types.
  returned: changed
  type: dict
  sample:
    url_categories: true
    url_datagroups: false
    ip_datagroups: true
o365_categories:
  description: The configured O365 URL categories.
  returned: changed
  type: dict
schedule:
  description: The configured update schedule.
  returned: changed
  type: dict
  sample:
    periods: daily
    run_time: "04:00"
status:
  description: The current O365 updater status read from the device.
  returned: always
  type: dict
  sample:
    description: "URLs exists - update bypassed"
    last_run: "2026-04-06 04:00"
    next_run: "2026-04-07 04:00 (Tomorrow)"
device_status:
  description: Per-device O365 updater status list read from the device.
  returned: always
  type: list
  elements: dict
  sample:
    - deviceId: bigip1
      status:
        description: "URLs exists - update bypassed"
        last_run: "2026-04-06 04:00"
        next_run: "2026-04-07 04:00 (Tomorrow)"
'''

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

from ansible.module_utils.basic import (
    AnsibleModule, missing_required_lib
)
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, sslo_version, check_sslo_provisioned
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)
from ..module_utils.compare import (
    compare_dictionary, cmp_simple_list,
)
from ..module_utils.constants import (
    min_sslo_version, max_sslo_version,
)


# Default system configuration values
_SYSTEM_DEFAULTS = dict(
    log_level=1,
    working_directory='/var/config/rest/iapps/f5-iappslx-ssl-orchestrator/nodejs/o365',
    retry_attempts=3,
    retry_delay=300,
)

_O365_WORKER_URI = '/mgmt/shared/iapp/f5-iappslx-ssl-orchestrator/o365UrlUpdateWorker'
_O365_GET_URI = _O365_WORKER_URI + '?operationType=allDevices'


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []

    returnables = [
        'endpoint',
        'service_areas',
        'outputs',
        'o365_categories',
        'only_required',
        'excluded_urls',
        'included_urls',
        'excluded_ips',
        'system',
        'schedule',
        'is_install',
        'fetch_now',
        'replicate_included_urls',
        'status',
        'device_status',
    ]

    updatables = [
        'endpoint',
        'service_areas',
        'outputs',
        'o365_categories',
        'only_required',
        'excluded_urls',
        'included_urls',
        'excluded_ips',
        'system',
        'schedule',
    ]


class ApiParameters(Parameters):
    @property
    def endpoint(self):
        return self._values.get('endpoint', None)

    @property
    def service_areas(self):
        return self._values.get('service_areas', None)

    @property
    def outputs(self):
        return self._values.get('outputs', None)

    @property
    def o365_categories(self):
        return self._values.get('o365_categories', None)

    @property
    def only_required(self):
        return self._values.get('only_required', None)

    @property
    def excluded_urls(self):
        return self._values.get('excluded_urls', None)

    @property
    def included_urls(self):
        return self._values.get('included_urls', None)

    @property
    def excluded_ips(self):
        return self._values.get('excluded_ips', None)

    @property
    def system(self):
        return self._values.get('system', None)

    @property
    def schedule(self):
        return self._values.get('schedule', None)

    @property
    def status(self):
        return self._values.get('status', None)

    @property
    def device_status(self):
        return self._values.get('deviceStatus', None)


class ModuleParameters(Parameters):
    @property
    def endpoint(self):
        return self._values.get('endpoint', None)

    @property
    def service_areas(self):
        raw = self._values.get('service_areas', None)
        if raw is None:
            return None
        return dict(
            common=bool(raw.get('common', True)),
            exchange=bool(raw.get('exchange', True)),
            sharepoint=bool(raw.get('sharepoint', True)),
            skype=bool(raw.get('skype', True)),
        )

    @property
    def outputs(self):
        raw = self._values.get('outputs', None)
        if raw is None:
            return None
        return dict(
            url_categories=bool(raw.get('url_categories', True)),
            url_datagroups=bool(raw.get('url_datagroups', False)),
            ip_datagroups=bool(raw.get('ip_datagroups', True)),
        )

    @property
    def o365_categories(self):
        raw = self._values.get('o365_categories', None)
        if raw is None:
            return None
        return dict(
            all=bool(raw.get('all', True)),
            optimize=bool(raw.get('optimize', True)),
            default=bool(raw.get('default', True)),
            allow=bool(raw.get('allow', True)),
        )

    @property
    def only_required(self):
        return self._values.get('only_required', None)

    @property
    def excluded_urls(self):
        return self._values.get('excluded_urls', [])

    @property
    def included_urls(self):
        raw = self._values.get('included_urls', None)
        if raw is None:
            return None
        return dict(
            all=raw.get('all', []) or [],
            optimized=raw.get('optimized', []) or [],
            default=raw.get('default', []) or [],
            allow=raw.get('allow', []) or [],
        )

    @property
    def excluded_ips(self):
        return self._values.get('excluded_ips', [])

    @property
    def system(self):
        raw = self._values.get('system', None)
        if raw is None:
            return None
        ca_bundle = raw.get('ca_bundle', None)
        if not ca_bundle:
            raise F5ModuleError(
                "The 'ca_bundle' field is required when specifying the 'system' parameter."
            )
        result = dict(
            log_level=raw.get('log_level', _SYSTEM_DEFAULTS['log_level']),
            ca_bundle=ca_bundle,
            working_directory=raw.get('working_directory', _SYSTEM_DEFAULTS['working_directory']),
            retry_attempts=raw.get('retry_attempts', _SYSTEM_DEFAULTS['retry_attempts']),
            retry_delay=raw.get('retry_delay', _SYSTEM_DEFAULTS['retry_delay']),
        )
        return result

    @property
    def schedule(self):
        raw = self._values.get('schedule', None)
        if raw is None:
            return None

        periods = raw.get('periods', None)
        if periods is None:
            raise F5ModuleError("The 'periods' field is required within 'schedule'.")

        run_time = raw.get('run_time', None)
        run_date_raw = raw.get('run_date')
        run_date = run_date_raw if run_date_raw is not None else 1
        start_date = raw.get('start_date', '')
        start_time = raw.get('start_time', '')

        if periods in ('daily', 'weekly', 'monthly') and run_time is None:
            raise F5ModuleError(
                f"The 'run_time' field is required when schedule periods is '{periods}'."
            )
        if periods == 'weekly' and not isinstance(run_date, int):
            raise F5ModuleError(
                "The 'run_date' field must be an integer (1=Monday through 7=Sunday) "
                "when schedule periods is 'weekly'."
            )
        if periods == 'monthly' and not isinstance(run_date, int):
            raise F5ModuleError(
                "The 'run_date' field must be an integer (day of month, 1-31) "
                "when schedule periods is 'monthly'."
            )

        return dict(
            periods=periods,
            run_date=run_date,
            run_time=run_time if run_time else '',
            start_date=start_date or '',
            start_time=start_time or '',
        )

    @property
    def is_install(self):
        return self._values.get('is_install', True)

    @property
    def fetch_now(self):
        return self._values.get('fetch_now', False)

    @property
    def replicate_included_urls(self):
        return self._values.get('replicate_included_urls', False)

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

    @property
    def service_areas(self):
        return compare_dictionary(self.want.service_areas, self.have.service_areas)

    @property
    def outputs(self):
        return compare_dictionary(self.want.outputs, self.have.outputs)

    @property
    def o365_categories(self):
        return compare_dictionary(self.want.o365_categories, self.have.o365_categories)

    @property
    def included_urls(self):
        return compare_dictionary(self.want.included_urls, self.have.included_urls)

    @property
    def excluded_urls(self):
        return cmp_simple_list(self.want.excluded_urls, self.have.excluded_urls)

    @property
    def excluded_ips(self):
        return cmp_simple_list(self.want.excluded_ips, self.have.excluded_ips)

    @property
    def system(self):
        return compare_dictionary(self.want.system, self.have.system)

    @property
    def schedule(self):
        return compare_dictionary(self.want.schedule, self.have.schedule)


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()
        self.version = None
        self._current_status = None
        self._current_device_status = None

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        changed = {}
        for k in Parameters.updatables:
            change = diff.compare(k)
            if change is None:
                continue
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
        result = dict()
        self.check_sslo_version()
        check_sslo_provisioned(self.client)
        changed = self.present()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))

        # Always include current device status in output
        if self._current_status is not None:
            result['status'] = self._current_status
        if self._current_device_status is not None:
            result['device_status'] = self._current_device_status

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

    def should_update(self):
        return self._update_changed_options()

    def update(self):
        self.have = self.read_current_from_device()
        config_changed = self.should_update()
        # fetch_now=True always forces a POST regardless of config changes
        if not config_changed and not self.want.fetch_now:
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def exists(self):
        """Check if O365 updater config exists on device by performing a GET."""
        response = self.client.get(_O365_GET_URI)
        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        # If endpoint key is present the config exists
        contents = response['contents']
        if contents.get('endpoint', None):
            self._current_status = contents.get('status', None)
            self._current_device_status = contents.get('deviceStatus', None)
            return True
        return False

    def _build_payload(self):
        """Build the POST payload from module parameters and existing device config."""
        want = self.want

        # Resolve system block — fall back to have if not provided
        if want.system is not None:
            system = want.system
        elif self.have and self.have.system:
            system = self.have.system
        else:
            raise F5ModuleError(
                "The 'system' parameter with at least 'ca_bundle' is required to configure "
                "the O365 URL/Datagroup Updater."
            )

        configs = dict(
            endpoint=want.endpoint,
            service_areas=want.service_areas if want.service_areas is not None
            else (self.have.service_areas or dict(common=True, exchange=True, sharepoint=True, skype=True)),
            outputs=want.outputs if want.outputs is not None
            else (self.have.outputs or dict(url_categories=True, url_datagroups=False, ip_datagroups=True)),
            o365_categories=want.o365_categories if want.o365_categories is not None
            else (self.have.o365_categories or dict(all=True, optimize=True, default=True, allow=True)),
            only_required=want.only_required if want.only_required is not None
            else (self.have.only_required if self.have and self.have.only_required is not None else True),
            excluded_urls=want.excluded_urls if want.excluded_urls is not None else [],
            included_urls=want.included_urls if want.included_urls is not None
            else (self.have.included_urls or dict(all=[], optimized=[], default=[], allow=[])),
            excluded_ips=want.excluded_ips if want.excluded_ips is not None else [],
            system=system,
            schedule=want.schedule if want.schedule is not None
            else (self.have.schedule or dict(periods='none', run_date=1, run_time='', start_date='', start_time='')),
        )

        # Carry over read-only fields from existing config if available
        if self.have and self.have.status:
            configs['status'] = self.have.status

        payload = dict(
            configs=configs,
            operation='save',
            operationType='allDevices',
            isInstall=want.is_install,
            isFetchNow=want.fetch_now,
            isReplincludeUrls=want.replicate_included_urls,
        )
        return payload

    def create_on_device(self):
        payload = self._build_payload()
        response = self.client.post(_O365_WORKER_URI, data=payload)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(
                f"Failed to create O365 URL/Datagroup Updater configuration: {response['contents']}"
            )
        # Refresh status after successful create
        self._refresh_status()

    def update_on_device(self):
        payload = self._build_payload()
        response = self.client.post(_O365_WORKER_URI, data=payload)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(
                f"Failed to update O365 URL/Datagroup Updater configuration: {response['contents']}"
            )
        # Refresh status after successful update
        self._refresh_status()

    def read_current_from_device(self):
        response = self.client.get(_O365_GET_URI)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(
                f"Failed to read O365 URL/Datagroup Updater configuration: {response['contents']}"
            )
        contents = response['contents']
        self._current_status = contents.get('status', None)
        self._current_device_status = contents.get('deviceStatus', None)
        return ApiParameters(params=contents)

    def _refresh_status(self):
        """Re-read device after write to update status output."""
        response = self.client.get(_O365_GET_URI)
        if response['code'] in [200, 201, 202]:
            contents = response['contents']
            self._current_status = contents.get('status', None)
            self._current_device_status = contents.get('deviceStatus', None)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            endpoint=dict(
                type='str',
                required=True,
                choices=['Worldwide', 'USGovDoD', 'USGovGCCHigh', 'China', 'Germany'],
            ),
            service_areas=dict(
                type='dict',
                options=dict(
                    common=dict(type='bool', default=True),
                    exchange=dict(type='bool', default=True),
                    sharepoint=dict(type='bool', default=True),
                    skype=dict(type='bool', default=True),
                ),
            ),
            outputs=dict(
                type='dict',
                options=dict(
                    url_categories=dict(type='bool', default=True),
                    url_datagroups=dict(type='bool', default=False),
                    ip_datagroups=dict(type='bool', default=True),
                ),
            ),
            o365_categories=dict(
                type='dict',
                options=dict(
                    all=dict(type='bool', default=True),
                    optimize=dict(type='bool', default=True),
                    default=dict(type='bool', default=True),
                    allow=dict(type='bool', default=True),
                ),
            ),
            only_required=dict(type='bool', default=True),
            excluded_urls=dict(type='list', elements='str', default=[]),
            included_urls=dict(
                type='dict',
                options=dict(
                    all=dict(type='list', elements='str'),
                    optimized=dict(type='list', elements='str'),
                    default=dict(type='list', elements='str'),
                    allow=dict(type='list', elements='str'),
                ),
            ),
            excluded_ips=dict(type='list', elements='str', default=[]),
            system=dict(
                type='dict',
                options=dict(
                    log_level=dict(type='int', default=1),
                    ca_bundle=dict(type='str', required=True),
                    working_directory=dict(
                        type='str',
                        default='/var/config/rest/iapps/f5-iappslx-ssl-orchestrator/nodejs/o365',
                    ),
                    retry_attempts=dict(type='int', default=3),
                    retry_delay=dict(type='int', default=300),
                ),
            ),
            schedule=dict(
                type='dict',
                options=dict(
                    periods=dict(
                        type='str',
                        required=True,
                        choices=['none', 'daily', 'weekly', 'monthly'],
                    ),
                    run_time=dict(type='str'),
                    run_date=dict(type='int'),
                    start_date=dict(type='str', default=''),
                    start_time=dict(type='str', default=''),
                ),
            ),
            is_install=dict(type='bool', default=True),
            fetch_now=dict(type='bool', default=False),
            replicate_included_urls=dict(type='bool', default=False),
            timeout=dict(type='int', default=300),
            state=dict(
                type='str',
                default='present',
                choices=['present'],
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
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
