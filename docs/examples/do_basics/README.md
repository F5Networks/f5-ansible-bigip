# DO Basics

This example will deploy Declarative Onboarding using the **bigip_do_deploy** module. The input for the declaration in this example is a static JSON file but in a production environment it would most likely be templatized using **JINJA2**.

* **Playbook:**: `do_basics.yaml`
* **Connection Info:**: `../host_vars`

Run the playbook from the examples root directory where the ansible.cfg is located.

#### Deploy Declaration


* Deploy DO declaration `do_basics/declarations/do.json`

```ansible-playbook do_basics/do_basics.yaml```

```
    - name: Deploy or Update
      f5networks.f5_bigip.bigip_do_deploy:
          content: "{{ lookup('file', 'declarations/do.json') }}"
```

* To modify the current config, update `do_basics/declarations/do.json` and re-run the playbook

#### Delete DO Config

Declarative Onboarding does not support DELETE. To update a configuration or remove objects simply update the declaration and re-submit it.

#### Notes

* It is possible to extend the duration that ansible will check for DO to complete. This is useful in case your environment takes a particularly long time to reboot. Please check the module docs for options when using the **timeout** parameter within the module.

```
    - name: Deploy or Update
      f5networks.f5_bigip.bigip_do_deploy:
          content: "{{ lookup('file', 'declarations/do.json') }}"
          timeout: 3600
```