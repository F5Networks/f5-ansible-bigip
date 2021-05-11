# TS Basics

This example will deploy a Telemetry Streaming declaration using the **bigip_ts_deploy** module. The input for the declaration in this example is a static JSON file but in a production environment it would most likely be templatized using **JINJA2**.

* **Playbook:**: `ts_basics.yaml`
* **Connection Info:**: `../host_vars`

Run the playbook from the examples root directory where the ansible.cfg is located.

#### Deploy Declaration

* Deploy new TS declaration `ts_basics/declarations/ts.json`

```ansible-playbook ts_basics/ts_basics.yaml```

```
    - name: Deploy or Update
      f5networks.f5_bigip.bigip_ts_deploy:
          content: "{{ lookup('file', 'declarations/ts.json') }}"
```

* To modify the current config, update `ts_basics/declarations/ts.json` and re-run the playbook

#### Delete TS Config

While TS does not support the Delete method, the module will clear out the declaration for you and POST the empty declaration to the endpoint which will remove the current TS declaration.

```ansible-playbook ts_basics/ts_basics.yaml --tags "delete"```

```
    - name: Clear Declaration
      f5networks.f5_bigip.bigip_ts_deploy:
          state: absent
      tags: [ never, delete ]
```