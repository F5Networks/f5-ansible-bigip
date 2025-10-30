# F5 BIG-IP Declarative Collection for Ansible

## Description
This collection provides Ansible modules and plugins for managing F5 BIG-IP and BIG-IQ devices using declarative APIs such as AS3, DO, TS, and CFE. It also includes imperative modules for operational tasks not covered by declarative workflows, such as saving and backing up configs, uploading security policies, certs/keys, and gathering device information. This collection is designed for network and automation engineers who want to automate F5 device management, streamline operations, and ensure consistency across environments.

**Note:** This collection is not intended to replace the existing [imperative_collection].

## Requirements
- Ansible >= 2.16
- Python >= 3.9
- See the `requirements.txt` for Python package dependencies.

## Installation
Install the collection from Ansible Galaxy:

```
ansible-galaxy collection install f5networks.f5_bigip
```

To specify the installation location, use the `-p` option. For example:

```
ansible-galaxy collection install f5networks.f5_bigip -p ./collections
```

If you specify a folder, make sure to update your `ansible.cfg` so Ansible will check this folder as well. For example, add:

```
collections_paths = ./collections
```
to your `ansible.cfg`.

Or include it in a `requirements.yml` file:

```yaml
collections:
  - name: f5networks.f5_bigip
```

To upgrade to the latest version:
```
ansible-galaxy collection install f5networks.f5_bigip --upgrade
```

To install a specific version (e.g., 1.0.0):
```
ansible-galaxy collection install f5networks.f5_bigip:==1.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

> **Note:** After installation, ensure your `ansible.cfg` includes the correct `collections_paths` if you used a custom path.

## Tips

- You can use this declarative collection alongside the previous imperative collection for maximum flexibility.
- If migrating from the imperative collection, you can continue to use your existing provider variables and reference them from the new httpapi connection variables. For example:

```yaml
ansible_host: "{{ provider.server }}"
ansible_user: "{{ provider.user }}"
ansible_httpapi_password: "{{ provider.password }}"
ansible_httpapi_port: "{{ provider.server_port }}"
ansible_network_os: f5networks.f5_bigip.bigip
ansible_httpapi_use_ssl: yes
ansible_httpapi_validate_certs: "{{ provider.validate_certs }}"
```

## Execution Environment (EE) Guide

You can run this collection inside an Ansible Execution Environment (EE) container. This ensures all required package dependencies and minimum supported Python versions are installed in an isolated container, minimizing environment-related issues during runtime.

To use the collection in an EE, add it to your `requirements.yml` file. For example:

```yaml
collections:
  - name: ansible.netcommon
    version: ">=2.0.0"
  - name: f5networks.f5_bigip
```



When building your EE container, include this requirements file. For more information on building and using EEs, see the [F5 Execution Environment Usage Guide] and the [Ansible EE documentation].


## Testing
This collection has been tested on:
- F5 BIG-IP and BIG-IQ virtual editions
- Supported Ansible versions (>=2.16)
- Python 3.9+

Testing includes unit, integration, and system tests. Some modules may require access to a live F5 device or a suitable test environment. Known exceptions and workarounds are documented in the module documentation.

## Support
As Red Hat Ansible Certified Content, this collection is entitled to support through the Ansible Automation Platform (AAP) using the **Create issue** button on the top right corner. If a support case cannot be opened with Red Hat and the collection has been obtained either from Galaxy or GitHub, there may be community help available on the [Ansible Forum](https://forum.ansible.com/) or you can report issues on the [GitHub issue tracker](https://github.com/F5Networks/f5-ansible-bigip/issues).

## Release Notes
See the [Changelog](https://clouddocs.f5.com/products/orchestration/ansible/devel/f5_bigip/CHANGELOG.html) for release notes.


## License Information
This collection is licensed under the [GPLv3 License](https://www.gnu.org/licenses/gpl-3.0.txt). See the LICENSE file included in the collection for details.

## Contributor License Agreement
Individuals or business entities who contribute to this project must complete and submit the [F5 Contributor License Agreement](https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/contributor.html) to Ansible_CLA@f5.com prior to their code submission being included in this project.

## Copyright
Copyright 2025 F5 Networks Inc.


[F5 Ansible Solutions]: https://clouddocs.f5.com/products/orchestration/ansible/devel/
[Ansible EE documentation]: https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.5/html/creating_and_using_execution_environments/index
[F5 Execution Environment Usage Guide]: https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/exec-env.html
[f5execenv]: https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/exec-env.html
[F5 Networks]: http://www.f5.com

[imperative_collection]: https://galaxy.ansible.com/f5networks/f5_modules