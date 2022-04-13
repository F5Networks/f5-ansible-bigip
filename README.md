# F5 Declarative Collection for Ansible

A collection focusing on managing F5 BIG-IP/BIG-IQ through declarative APIs such as AS3, DO, TS, and CFE. 
The collection does include key imperative modules as well for managing some resources and operational tasks 
that are not part of declarative workflows. These would include actions such as saving config, backing up config, 
uploading security policies, uploading crts/keys, gathering info, etc.

**Note:** This Collection is not currently intended to replace the existing [imperative_collection].

## Python Version
This collection is supported on Python 3.6 and above.

## Collections Daily Build


We offer a daily build of our most recent collection [dailybuild]. Use this Collection to test the most
recent Ansible module updates between releases. You can also install development build directly from GitHub see [repoinstall].

### Install from GitHub
```bash

ansible-galaxy collection install git+https://github.com/F5Networks/f5-ansible-bigip.git#ansible_collections/f5networks/f5_bigip
```

### Install from the daily build file
```bash

    ansible-galaxy collection install <collection name> -p ./collections
    e.g.
    ansible-galaxy collection install f5networks-f5_bigip-devel.tar.gz -p ./collections
```

> **_NOTE:_**  `-p` is the location in which the collection will be installed. This location should be defined in the path for
    Ansible to search for collections. An example of this would be adding ``collections_paths = ./collections``
    to your **ansible.cfg**
    
## Tips

* You can leverage both this declarative collection and the previous imperative collection at the same time.
* If you are migrating from the imperative collection, you can leave the provider variables and reference them from 
  the new httpapi connection variables:

```yaml
   ansible_host: "{{ provider.server }}"
   ansible_user: "{{ provider.user }}"
   ansible_httpapi_password: "{{ provider.password }}"
   ansible_httpapi_port: "{{ provider.server_port }}"
   ansible_network_os: f5networks.f5_bigip.bigip
   ansible_httpapi_use_ssl: yes
   ansible_httpapi_validate_certs: "{{ provider.validate_certs }}"
```

## Bugs, Issues
   
Please file any bugs, questions, or enhancement requests by using [ansible_issues]. For details, see [ansiblehelp].

## Your ideas


What types of modules do you want created? If you have a use case and can sufficiently describe the behavior 
you want to see, open an issue and we will hammer out the details.

If you've got the time, consider sending an email that introduces yourself and what you do. 
We love hearing about how you're using the F5_BIGIP collection for Ansible.

> **_NOTE:_** **This repository is a mirror, only issues submissions are accepted.**

- Wojciech Wypior and the F5 team - solutionsfeedback@f5.com

## Copyright

Copyright 2022 F5 Networks Inc.


## License

### GPL V3

This License does not grant permission to use the trade names, trademarks, service marks, or product names of the 
Licensor, except as required for reasonable and customary use in describing the origin of the Work.

See [License].

### Contributor License Agreement
Individuals or business entities who contribute to this project must complete and submit the 
[F5 Contributor License Agreement] to ***Ansible_CLA@f5.com*** prior to their code submission 
being included in this project.


[repoinstall]: https://docs.ansible.com/ansible/latest/user_guide/collections_using.html#installing-a-collection-from-a-git-repository
[imperative_collection]: https://galaxy.ansible.com/f5networks/f5_modules
[dailybuild]: https://f5-ansible.s3.amazonaws.com/collections/f5networks-f5_bigip-devel.tar.gz
[License]: https://github.com/f5devcentral/f5-ansible-bigip/blob/master/COPYING
[ansible_issues]: https://github.com/F5Networks/f5-ansible-bigip/issues
[ansiblehelp]: http://clouddocs.f5.com/products/orchestration/ansible/devel/
[F5 Contributor License Agreement]: http://clouddocs.f5.com/products/orchestration/ansible/devel/usage/contributor.html