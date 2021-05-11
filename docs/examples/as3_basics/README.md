# AS3 Basics

This example will create a Virtual with corresponding elements such as Pool, profiles, monitors, etc using the **bigip_as3_deploy** module. The input for the declaration in this example is a static JSON file but in a production environment it would most likely be templatized using **JINJA2**.

* **Playbook:**: `as3_basics.yaml`
* **Connection Info:**: `../host_vars`

Run the playbook from the examples root directory where the ansible.cfg is located.


#### Deploy Declaration

* Create new BIG-IP config located in `as3_basics/declarations/as3.json`

```ansible-playbook as3_basics/as3_basics.yaml```

```
    - name: Deploy or Update
      f5networks.f5_bigip.bigip_as3_deploy:
          content: "{{ lookup('file', 'declarations/as3.json') }}"
```

* To modify the current config, update `as3_basics/declarations/as3.json` and re-run the playbook

#### Delete Tenant
* To delete a specific Tenant, specify the tenant parameter with the name of the tenant you would like to remove.
  * Run the task in the playbook with this example 
  
  
```ansible-playbook as3_basics/as3_basics.yaml --tags "delete"```

```
    - name: Delete Specified Tenant
      f5networks.f5_bigip.bigip_as3_deploy:
          state: absent
          tenant: ansible
      tags: [ never, delete ]
```

#### Delete All Tenants
* To delete all **tenant**, specify the tenant parameter as **all**
  * Run the task in the playbook with the following tag


```ansible-playbook as3_basics/as3_basics.yaml --tags "delete_all"```

```
    - name: Delete All Tenants
      f5networks.f5_bigip.bigip_as3_deploy:
          state: absent
          tenant: all
      tags: [ never, delete_all ]
```