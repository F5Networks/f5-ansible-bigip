# Create an app with f5_modules vs f5_bigip

In this example we have 2 playbooks which compare creating BIG-IP objects using an imperative workflow (f5_modules) vs using a declarative workflow (f5_bigip).

Both playbooks take identical input other than the IP addresses and connection method

**Run the playbook from the examples root directory where the ansible.cfg is located.**

## Imperative (f5_modules)

**Playbook:** `app_previous.yaml`

#### Connection Method
* connection: local

    ```
    provider:
        server: bigip-hostname
        server_port: 443
        user: admin
        password: SuperSecret
        validate_certs: false
    ```

```ansible-playbook f5_modules-f5_bigip-comparison/app_previous.yaml```

#### Playbook Logic:

* Uses JINJA2 templating within each imperative module leveraging the **app** input variables.
* User must define tasks in the correct order for BIG-IP (create pool, then create pool members, then create virtual, etc)
* User must define backout steps in the reverse order in case of an error during execution (remove virtual, remove pool, etc)
  * If logic is not correct, backout is not guaranteed.
* Tested execution time: ~30s / app
* ~100 Lines of Tasks

## Declarative (f5_bigip)

**Playbook:** `app_new.yaml`

#### Connection Method
* connection: httpapi

    ```
    ansible_host: bigip-hostname
    ansible_user: admin
    ansible_httpapi_password: SuperSecret
    ansible_httpapi_port: 443
    ansible_network_os: f5networks.f5_bigip.bigip
    ansible_httpapi_use_ssl: yes
    ansible_httpapi_validate_certs: no
    ```

```ansible-playbook f5_modules-f5_bigip-comparison/app_new.yaml```

#### Playbook Logic:

* Uses JINJA2 templating to update an **AS3** template leveraging the **app** input variables.
* There is only 1 task, domain knowledge of order is not needed.
* AS3 is atomic in that it is "all or nothing". No backout steps or tasks are needed. If the task fails, no changes are made.
* Tested execution time: ~12s + minimum increase per additional App.
* ~3 Lines of Tasks

## Tips:

* You can have both collections installed at the same time.
* If you are migrating from the imperative collection, you can leave the provider variables and reference them from the new httpapi connection variables:

    ```
    ansible_host: "{{ provider.server }}"
    ansible_user: "{{ provider.user }}"
    ansible_httpapi_password: "{{ provider.password }}"
    ansible_httpapi_port: "{{ provider.server_port }}"
    ansible_network_os: f5networks.f5_bigip.bigip
    ansible_httpapi_use_ssl: yes
    ansible_httpapi_validate_certs: "{{ provider.validate_certs }}"
    ```