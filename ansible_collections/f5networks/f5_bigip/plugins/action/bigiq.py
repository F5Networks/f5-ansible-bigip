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

from ansible.utils.display import Display
from ansible_collections.ansible.netcommon.plugins.action.network import ActionModule as ActionNetworkModule

# This file is a workaround for the time being not being used but is required so the action plugin from core or another
# collection is not used.

display = Display()


class ActionModule(ActionNetworkModule):
    def run(self, tmp=None, task_vars=None):
        result = super(ActionModule, self).run(task_vars=task_vars)
        return result
