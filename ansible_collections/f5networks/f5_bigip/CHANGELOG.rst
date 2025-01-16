=============================================
F5Networks F5\_BIGIP Collection Release Notes
=============================================

.. contents:: Topics

v3.10.0
=======

v3.9.0
======

Minor Changes
-------------

- bigip_as3_deploy - added controls parameter.

v3.8.2
======

v3.8.1
======

v3.8.0
======

v3.7.0
======

v3.6.2
======

v3.6.1
======

v3.6.0
======

Bugfixes
--------

- bigip_as3_deploy - Fixed PerApp Deployment for Version >= 3.5

v3.5.1
======

v3.5.0
======

Bugfixes
--------

- bigip_security_log_profile.py - added parameters to configue application security log profile.

v3.4.0
======

Major Changes
-------------

- bigip_as3_deploy - added per-application deployment enhancement.

Bugfixes
--------

- bigip_software_install - fixed a bug that didn't let the user install software on an existing volume.
- bigip_sslo_service_icap - fixed issue - missing service_entry_ssl_profile, cpm_policies field.
- bigip_sslo_service_icap - fixed issue - missing vendor_info field.

v3.3.0
======

Minor Changes
-------------

- bigip_sslo_config_policy - updated documentation for policy_consumer.
- bigip_sslo_config_ssl - added the options to specify passphrases for private key and ca private key

Bugfixes
--------

- bigip_awaf_policy - fixed a bug that didn't let the user create a policy in a partition other than Common.
- bigip_ssl_key_cert - fixed an issue where the passphrase was not being properly send to the BIG-IP.
- bigip_sslo_config_policy - fixed issue - cant reference security policy.
- bigip_sslo_config_policy - resolved SSLO Security Policy modification issue.
- bigip_sslo_config_topology - set interception rule to custom when topology is outbound_l3 and port is provided.
- bigip_sslo_service_layer2 - fixed issue - missing vendor_info field.
- bigiq_as3_deploy - fixed flaw in code to make module work

v3.2.2
======

v3.2.1
======

Bugfixes
--------

- bigip_ssl_key_cert - fixed flaw in code to make module work with same key and cert name when true_names set to true

v3.1.1
======

v3.1.0
======

Minor Changes
-------------

- bigip_ssl_csr - Added option for Subject Alternative Name
- bigip_ucs_fetch - made changes to fetch tmos version before starting async task to prevent blocking blocking of the module

v3.0.0
======

Major Changes
-------------

- bigip_ssl_csr - removed force option, locally create csr files with the same name will no longer be overriden
- bigiq_device_info - removed bash command run over API as the util/bash endpoint have been removed as a security risk
- bigiq_device_info - the module is guaranteed to work on BIG-IQ version 7.1 and above

Minor Changes
-------------

- bigip - added token_timeout option to allow specifying custom timeouts for TMOS tokens
- bigip_sslo_service_http - fix for bigip_sslo_service_http cannot create a service with an existing self-ip(#63)
- bigip_sslo_service_layer2 - make the deault value for ip_offset parameter to be 0 when creating a layer2 service

Bugfixes
--------

- bigip - fixed issue with httpapi plugin where expired tokens would not attempt plugin to re-authenticate
- bigip_device_info - fixed flaw in code to ignore fields that do not exist in the response for license info
- bigip_fast_application - corrected issue where pending state for deployments would cause module to error out, instead of waiting for the duration of the set timeout parameter

v2.1.0
======

Minor Changes
-------------

- bigip_ssl_key_cert - added an option to prevent adding .key and .crt extensions to key and cert names respectively

v2.0.0
======

Minor Changes
-------------

- bigip_do_deploy - added an option to dry run declaration
- bigip_sslo_service_http - refactored jinja templates to include a few conditional checks in devices_to and devices_from section

Removed Features (previously deprecated)
----------------------------------------

- Removed all VELOS related modules from collection, use dedicated F5OS collection to manage VELOS devices https://github.com/F5Networks/f5-ansible-f5os instead
- See porting guides section at https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/porting-guides.html

Bugfixes
--------

- bigip_as3_deploy - added better error reporting to declarative operations
- bigip_config - fixes issue with GET calls returning 503 errors during async task execution
- bigip_device_info - Included additional attributes for actions in ltm policy rules
- bigip_sslo_service_tap - make port_remap disbaled by default unless the user explicitly enables it by providing port value for port_remap
- bigip_ucs_fetch - fix a typo causing a bug that prevented ucs file from being encrypted with the provided passphrase

New Modules
-----------

- bigip_awaf_policy - Manage WAF policy with input parameters

v1.13.0
=======

Bugfixes
--------

- bigip_as3_deploy - fix in AS3 declaration to accommodate ADC class.
- bigip_fast_application - fix parsing of errors in the returned json payload

New Modules
-----------

- bigip_security_http_profile - Manage security HTTP profiles on a BIG-IP
- bigip_security_log_profile - Manage security log profiles on a BIG-IP
- bigip_security_ssh_profile - Manage SSH proxy security profiles on a BIG-IP
- bigip_security_ssh_profile_keys - Manage SSH proxy security key management on a BIG-IP
- bigip_security_ssh_profile_rules - Manage SSH proxy security profile rules on a BIG-IP

v1.12.0
=======

Major Changes
-------------

- bigip_sslo_config_ssl - changed type of parameters, block_expired and block_untrusted from bool tor string.

Minor Changes
-------------

- bigip_device_info - add data_increment parameter for better control of data gathering from API, addresses cases where large configurations were causing token timeouts during module operation
- bigip_device_info - added option for gathering info about device license.
- bigip_sslo_config_ssl - added parameters, server_ssl_options and client_ssl_options for SSL and TLS processing.
- bigip_ucs_fetch - add ability to only create UCS files without downloading

Bugfixes
--------

- bigip_sslo_service_layer2 - raise exception when ip_offset is not provided when creating a new layer2 service

v1.11.0
=======

Minor Changes
-------------

- bigip_fast_application - fix for module failure when state present.
- bigip_sslo_config_policy - yaml will fail if security policy already exists.
- bigip_sslo_config_ssl - added parameters for default sni and sni server name
- bigip_sslo_config_topology - the ssl settings value is passed as an array in versions 9.1 and above
- bigip_sslo_service_swg - added 9.x fixes for sslo service swg

Deprecated Features
-------------------

- See porting guides section at https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/porting-guides.html
- velos httpapi plugin - deprecated, use f5networks.f5os collection for connecting with VELOS devices.
- velos_partition - deprecated, use f5networks.f5os collection for managing VELOS devices.
- velos_partition_change_password - deprecated, use f5networks.f5os collection for managing VELOS devices.
- velos_partition_image - deprecated, use f5networks.f5os collection for managing VELOS devices.
- velos_partition_interface - deprecated, use f5networks.f5os collection for managing VELOS devices.
- velos_partition_lag - deprecated, use f5networks.f5os collection for managing VELOS devices.
- velos_partition_tenant - deprecated, use f5networks.f5os collection for managing VELOS devices.
- velos_partition_tenant_image - deprecated, use f5networks.f5os collection for managing VELOS devices.
- velos_partition_tenant_wait - deprecated, use f5networks.f5os collection for managing VELOS devices.
- velos_partition_vlan - deprecated, use f5networks.f5os collection for managing VELOS devices.
- velos_partition_wait - deprecated, use f5networks.f5os collection for managing VELOS devices.

Bugfixes
--------

- bigip_software_image - fixed permission and ownership of the uploaded image file
- bigip_ucs - fixed permission and ownership of the ucs file

v1.10.0
=======

Minor Changes
-------------

- bigip_qkview - added a new parameter, only_create_file

v1.9.0
======

Minor Changes
-------------

- bigip_sslo_config_topology - existing topologies can now be modified
- module_utils/teem.py - add additional telemetry data fields with relevant tests

Bugfixes
--------

- bigip_sslo_service_http - fixed delete operation for sslo http service

v1.8.1
======

Bugfixes
--------

- bigip_device_info - fixed pagination bug for VLANS data

v1.8.0
======

Minor Changes
-------------

- bigip_device_info - add fqdn related parameters to be gathered on nodes
- bigip_device_info - add parent to the data gathered for ServerSSL Profiles
- bigip_sslo_config_policy - add default rule customization option
- bigip_sslo_config_policy - renamed servercert_check parameter to server_cert_check
- bigip_sslo_config_policy - renamed ssl_forwardproxy_action parameter to ssl_action (https://github.com/F5Networks/f5-ansible-bigip/issues/24)

Bugfixes
--------

- bigip_sslo_config_policy - corrected typo in module parameters (https://github.com/F5Networks/f5-ansible-bigip/issues/26)
- bigip_sslo_config_policy - fix for 'pools' key error when rerunning module (https://github.com/F5Networks/f5-ansible-bigip/issues/30)

v1.7.0
======

Minor Changes
-------------

- bigip_device_info - add UCS archive info to data gathered
- bigiq_regkey_license - add addon_keys parameter to the module

Bugfixes
--------

- bigip_command - fixed a bug that interpreted a pipe symbol inside an input string as pipe used to combine commands
- bigip_device_info - backported PR https://github.com/F5Networks/f5-ansible/pull/2157

New Modules
-----------

- bigip_sslo_config_policy - Manage an SSL Orchestrator security policy
- bigip_sslo_config_topology - Manage an SSL Orchestrator Topology

v1.6.0
======

Minor Changes
-------------

- bigip_device_info - Added a new meta choice, packages, which groups information about as3, do, cfe and ts. This change was done to ensure users with non admin access can use this module to get information that does not require admin access.

Bugfixes
--------

- bigip_as3_deploy - better error reporting for AS3 multitenant deployments.
- bigip_device_info - fixed bug regarding handling of negated meta options.
- velos_partition - removed misleading information from the documentation, fixed invalid validation for ipv6_mgmt_address and ipv4_mgmt_address parameters.
- velos_partition_change_password - fixed a bug that resulted in request being sent to the wrong url.
- velos_partition_intrface - removed the logic to create new interfaces as they were not required, along with change in payload and endpoint.
- velos_partition_lag - fixed bugs related to the payload structure, improved functional tests.
- velos_partition_vlan - changed the payload structure.
- velos_tenant_image - minor changes to module to prevent early failures

New Modules
-----------

- bigip_sslo_config_authentication - Manage an SSL Orchestrator authentication object
- bigip_sslo_config_resolver - Manage the SSL Orchestrator DNS resolver config
- bigip_sslo_config_service_chain - Manage an SSL Orchestrator service chain
- bigip_sslo_config_ssl - Manage an SSL Orchestrator SSL configuration
- bigip_sslo_config_utility - Manage the set of SSL Orchestrator utility functions
- bigip_sslo_service_http - Manage an SSL Orchestrator http security device
- bigip_sslo_service_icap - Manage an SSL Orchestrator ICAP security device
- bigip_sslo_service_layer2 - Manage an SSL Orchestrator layer 2 security device
- bigip_sslo_service_layer3 - Manage an SSL Orchestrator layer 3 security device
- bigip_sslo_service_tap - Manage an SSL Orchestrator TAP security device

v1.5.0
======

Major Changes
-------------

- bigip_device_info - pagination logic has also been added to help with api stability.
- bigip_device_info - the module no longer gathers information from all partitions on device. This change will stabalize the module by gathering resources only from the given partition and prevent the module from gathering way too much information that might result in crashing.

Bugfixes
--------

- bigip_ucs_fetch - fixed random src parameter being returned to the user at the end of module run

Known Issues
------------

- Changed functional tests for bigip_device_info module by replacing legacy modules with bigip_command

v1.4.0
======

Major Changes
-------------

- Module bigip_ucs install state is now asynchronous, see https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/porting-guides.html for details

Minor Changes
-------------

- Add custom timeout parameter to bigip_lx_package, allowing users define the amount of time to wait for RPM installation

New Modules
-----------

- velos_partition_interface - Manage network interfaces on the VELOS partitions
- velos_partition_lag - Manage network interfaces on the VELOS partitions

v1.3.0
======

Major Changes
-------------

- Module bigip_config changed to be asynchronous, see https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/porting-guides.html for details

Minor Changes
-------------

- Add module to change velos partition user passwords
- Add module to manage velos partition
- Add module to manage velos partition vlans

New Modules
-----------

- velos_partition - Manage VELOS chassis partitions
- velos_partition_change_password - Provides access to VELOS partition user authentication methods
- velos_partition_vlan - Manage VLANs on VELOS partitions
- velos_partition_wait - Wait for a VELOS partition to match a condition before continuing

v1.2.0
======

Minor Changes
-------------

- Add module to manage velos partition images

Bugfixes
--------

- Fix a number of on_device methods in bigip_device_info to prevent key errors during device query
- Fix from v1 https://github.com/F5Networks/f5-ansible/pull/2092
- Fix from v1 https://github.com/F5Networks/f5-ansible/pull/2099

v1.1.0
======

Major Changes
-------------

- Module bigip_ucs_fetch changed to be asynchronous, see https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/porting-guides.html for details

Minor Changes
-------------

- Add additional parameters to bigip_ssl_csr module
- Add bigip_software_image module to manage software images on BIG-IP
- Add bigip_software_install module to manage software installations on BIG-IP
- Add new module to check for VELOS tenant state
- Add new module to manage VELOS tenant images on partition
- Add new module to manage VELOS tenants on partition
- Add vcmp guest module for configuring and managing vcmp guests
- New httpapi plugin for velos platform

Bugfixes
--------

- Fix snat pool issue in device info module
- Include serialNumber for ssl-certs gather_subset issue-2041

New Plugins
-----------

Httpapi
~~~~~~~

- velos - HttpApi Plugin for VELOS devices

New Modules
-----------

- bigip_software_image - Manage software images on a BIG-IP
- bigip_software_install - Install software images on a BIG-IP
- bigip_vcmp_guest - Manages vCMP guests on a BIG-IP
- velos_tenant - Manage Velos tenants
- velos_tenant_image - Manage Velos tenant images
- velos_tenant_wait - Wait for a Velos condition before continuing

v1.0.0
======

New Plugins
-----------

Httpapi
~~~~~~~

- bigip - HttpApi Plugin for BIG-IP devices
- bigiq - HttpApi Plugin for BIG-IQ devices

New Modules
-----------

- bigip_apm_policy_fetch - Exports the APM policy or APM access profile from remote nodes.
- bigip_apm_policy_import - Manage BIG-IP APM policy or APM access profile imports
- bigip_as3_deploy - Manages AS3 declarations sent to BIG-IP
- bigip_asm_policy_fetch - Exports the ASM policy from remote nodes.
- bigip_asm_policy_import - Manage BIG-IP ASM policy imports
- bigip_cfe_deploy - Manages CFE declarations sent to BIG-IP
- bigip_command - Run TMSH and BASH commands on F5 devices
- bigip_config - Manage BIG-IP configuration sections
- bigip_configsync_action - Perform different actions related to config-sync
- bigip_device_info - Collect information from F5 BIG-IP devices
- bigip_do_deploy - Manages DO declarations sent to BIG-IP
- bigip_fast_application - Manages FAST application declarations sent to BIG-IP
- bigip_fast_template - Manages FAST template sets on BIG-IP
- bigip_imish_config - Manage BIG-IP advanced routing configuration sections
- bigip_lx_package - Manages Javascript LX packages on a BIG-IP
- bigip_qkview - Manage QKviews on the device
- bigip_ssl_csr - Create SSL CSR files on the BIG-IP
- bigip_ssl_key_cert - Import/Delete SSL keys and certs from BIG-IP
- bigip_ssl_pkcs12 - Manage BIG-IP PKCS12 certificates/keys
- bigip_ts_deploy - Manages TS declarations sent to BIG-IP
- bigip_ucs - Manage upload, installation, and removal of UCS files
- bigip_ucs_fetch - Fetches a UCS file from remote nodes
- bigiq_as3_deploy - Manages AS3 declarations sent to BIG-IQ
- bigiq_device_discovery - Manage BIG-IP devices through BIG-IQ
- bigiq_device_info - Collect information from F5 BIG-IQ devices
- bigiq_do_deploy - Manages DO declarations sent to BIG-IQ
- bigiq_regkey_license - Manages licenses in a BIG-IQ registration key pool
- bigiq_regkey_license_assignment - Manage regkey license assignment on BIG-IPs from a BIG-IQ
- bigiq_regkey_pool - Manages registration key pools on BIG-IQ
- bigiq_utility_license - Manage utility licenses on a BIG-IQ
- bigiq_utility_license_assignment - Manage utility license assignment on BIG-IPs from a BIG-IQ
