#
# (c) 2016 Red Hat Inc.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import sys
from ansible.module_utils._text import to_text
from ansible.module_utils.connection import Connection
from ansible.utils.display import Display

from ansible_collections.ansible.netcommon.plugins.action.network import ActionModule as ActionNetworkModule


display = Display()


class ActionModule(ActionNetworkModule):
    def run(self, task_vars=None):
        self._config_module = True if self._task.action == 'bigip_imish_config' else False
        pc = self._play_context

        if self._play_context.connection == 'network_cli':
            display.vvv('using connection plugin %s' % pc.connection, pc.remote_addr)
            connection = self._shared_loader_obj.connection_loader.get('persistent', pc, sys.stdin)

            socket_path = connection.run()
            display.vvvv('socket_path: %s' % socket_path, pc.remote_addr)
            if not socket_path:
                return {
                    'failed': True,
                    'msg': 'Unable to open shell. Please see: '
                           'https://docs.ansible.com/ansible/network_debug_troubleshooting.html#unable-to-open-shell'
                }

            task_vars['ansible_socket'] = socket_path

            conn = Connection(self._connection.socket_path)
            out = conn.get_prompt()
            while '(config' in to_text(out, errors='surrogate_then_replace').strip():
                display.vvvv('wrong context, sending exit to device', pc.remote_addr)
                conn.send_command('exit')
                out = conn.get_prompt()

        play_vars = task_vars["vars"]
        use_proxy = play_vars.get("ansible_httpapi_use_proxy")
        if bool(use_proxy):
            self.set_proxy_vars(task_vars.get("environment"))

        result = super(ActionModule, self).run(task_vars=task_vars)
        return result

    def set_proxy_vars(self, env):
        if not env:
            return

        proxy_vars = dict()

        for i in env:
            proxy_vars.update(i)

        if 'https_proxy' in proxy_vars:
            os.environ['https_proxy'] = proxy_vars['https_proxy']

        if 'http_proxy' in proxy_vars:
            os.environ['http_proxy'] = proxy_vars['http_proxy']

        if 'HTTPS_PROXY' in proxy_vars:
            os.environ['HTTPS_PROXY'] = proxy_vars['HTTPS_PROXY']

        if 'HTTP_PROXY' in proxy_vars:
            os.environ['HTTP_PROXY'] = proxy_vars['HTTP_PROXY']
