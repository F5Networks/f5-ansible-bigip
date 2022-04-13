# Use both collections in a single playbook

In this example we are leveraging imperative collection (f5_modules) to create some objects and to create
SSLO L2 Service object with declarative collection (f5_bigip).

**Run the playbook from the examples root directory where the ansible.cfg is located.**


## Points to consider:

* Requires that both collections (f5_modules and f5_bigip) are installed in your ./collections directory.
* Using the same variables for provider and httpapi will reduce the chance of errors:

    ```
    ansible_host: "{{ provider.server }}"
    ansible_user: "{{ provider.user }}"
    ansible_httpapi_password: "{{ provider.password }}"
    ansible_httpapi_port: "{{ provider.server_port }}"
    ansible_network_os: f5networks.f5_bigip.bigip
    ansible_httpapi_use_ssl: yes
    ansible_httpapi_validate_certs: "{{ provider.validate_certs }}"
    ```