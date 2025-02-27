delete = """
{
    "name": "{{ params.name }}",
    "inputProperties": [
        {
            "id": "f5-ssl-orchestrator-operation-context",
            "type": "JSON",
            "value": {
                "deploymentName": "{{ params.deployment_name }}",
                "deploymentReference": "{{ params.dep_ref }}",
                "deploymentType": "SERVICE",
                "operationType": "{{ params.operation }}",
                "version": {{ params.sslo_version }},
                "partition": "Common"
            }
        },
        {
            "id": "f5-ssl-orchestrator-network",
            "type": "JSON",
            "value": []
        },
        {
            "id": "f5-ssl-orchestrator-service",
            "type": "JSON",
            "value": {
                "existingBlockId": "{{ params.block_id }}",
                "name": "{{ params.deployment_name }}",
                "partition": "Common",
                "previousVersion": {{ params.sslo_version }},
                "version": {{ params.sslo_version }}
            }
        }
    ],
    "dataProperties":[],
    "configurationProcessorReference": {
        "link": "https://localhost/mgmt/shared/iapp/processors/f5-iappslx-ssl-orchestrator-gc"
    },
    "state": "BINDING"
}
"""
create_modify = """
{
    "name": "{{ params.name }}",
    "inputProperties":[
       {
          "id":"f5-ssl-orchestrator-operation-context",
          "type":"JSON",
          "value": {
                "version": {{ params.sslo_version }},
                "partition": "Common",
                "strictness": false,
                "operationType": "{{ params.operation }}",
                "deploymentName": "{{ params.deployment_name }}",
                "deploymentType": "SERVICE"{% if params.dep_ref is defined %},
                "deploymentReference": "{{ params.dep_ref }}"{% endif %}
          }
       },
       {
          "id":"f5-ssl-orchestrator-network",
          "type":"JSON",
          "value": {% if params.use_exist_selfip %}[]{% else %}[{%  if params.devices_to.vlan is not defined or not params.auto_manage -%}
            {
                "name": "{{ params.devices_to.name }}",
                "partition": "Common",
                "strictness": false,
                "vlan":{
                    "name": "{{ params.devices_to.name }}",
                    "path": "{{ params.devices_to.path }}",
                    "create": {% if params.devices_to.interface is defined %}true{% else %}false{% endif %},
                    "modify": false,
                    "networkError": false{% if 'interface' in params.devices_to %},
                    "interface":{% if 'interface' in params.devices_to %}["{{ params.devices_to.interface }}"]
                    {% else %}[]{% endif %},
                    "networkInterface": {% if 'interface' in params.devices_to -%}
                    "{{ params.devices_to.interface }}"{% else %}""{% endif %},
                    "tag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to -%}
                    {{ params.devices_to.tag }}{% else %}0{% endif %},
                    "networkTag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to -%}
                    {{ params.devices_to.tag }}{% else %}0{% endif %}{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.devices_to.interface is defined or not params.auto_manage %}true{% else %}false{% endif %},
                    "modify": false,
                    "selfIp": "{{ params.devices_to.self_ip }}",
                    "netmask": "{{ params.devices_to.netmask }}",
                    "floating": false,
                    "HAstaticIpMap": []
                },
                "routeDomain":{
                    "id": 0,
                    "create": false
                },
                "existingBlockId": ""
             }{% if params.devices_from is defined and params.devices_from.vlan is not defined or not params.auto_manage -%},{% endif %}{% endif %}
             {% if params.devices_from is defined and params.devices_from.vlan is not defined or not params.auto_manage -%}
                {
                    "name": "{{ params.devices_from.name }}",
                    "partition": "Common",
                    "strictness": false,
                    "vlan":{
                        "name": "{{ params.devices_from.name }}",
                        "path": "{{ params.devices_from.path }}",
                        "create": {% if params.devices_from.interface is defined %}true{% else %}false{% endif %},
                        "modify": false,
                        "networkError": false{% if 'interface' in params.devices_from %},
                        "interface":{% if 'interface' in params.devices_from %}["{{ params.devices_from.interface }}"]
                        {% else %}[]{% endif %},
                        "networkInterface": {% if 'interface' in params.devices_from -%}
                        "{{ params.devices_from.interface }}"{% else %}""{% endif %},
                        "tag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from -%}
                        {{ params.devices_from.tag }}{% else %}0{% endif %},
                        "networkTag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from -%}
                        {{ params.devices_from.tag }}{% else %}0{% endif %}{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.devices_from.interface is defined or not params.auto_manage %}true{% else %}false{% endif %},
                    "modify": false,
                    "selfIp": "{{ params.devices_from.self_ip }}",
                    "netmask": "{{ params.devices_from.netmask }}",
                    "floating": false,
                    "HAstaticIpMap": []
                },
                "routeDomain":{
                    "id": 0,
                    "create": false
                },
                "existingBlockId":""
             }{% endif %}
          ]{% endif %}
       },
       {
          "id":"f5-ssl-orchestrator-service",
          "type":"JSON",
          "value":{
             "customService":{
                "name": "{{ params.deployment_name }}",
                "serviceType": "L3",
                "serviceSpecific":{
                    "name": "{{ params.deployment_name }}"
                },
                "serviceEntrySSLProfile": "{{ params.service_entry_sslprofile }}",
                "serviceReturnSSLProfile": "{{ params.service_return_sslprofile }}",
                "controlChannels": {{ params.control_channels | tojson }},
                "connectionInformation":{
                    "toBigipNetwork":{
                        "name": {% if params.use_exist_selfip or params.devices_from.vlan is defined and params.auto_manage %}"fromNetwork"{% else %}
                        "{{ params.devices_from.name }}"{% endif %},
                        "vlan":{
                            "path": "{{ params.devices_from.path }}",
                            "create": {% if params.devices_from.interface is defined %}true{% else %}false{% endif %},
                            "modify": false,
                            "selectedValue": "{{ params.devices_from.path }}",
                            "networkVlanValue": ""
                        },
                        "routeDomain":{
                            "id":0,
                            "create": false
                        },
                        "selfIpConfig":{
                            "create": {% if params.devices_from.interface is defined %}true{% else %}
                            {% if params.use_exist_selfip or (params.devices_from.vlan is defined and params.auto_manage) %}false
                            {% else %}true{% endif %}{% endif %},
                            "modify": false,
                            "autoValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0300::7/120"
                            {% else %}"198.19.96.7/25"{% endif %},
                            "selectedValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0300::7/120"
                            {% else %}""{% endif %},
                            "selfIp": "{{ params.devices_from.self_ip }}",
                            "netmask": "{{ params.devices_from.netmask }}",
                            "floating": false,
                            "HAstaticIpMap": []
                        },
                      "networkBlockId": {% if params.from_net_id is defined %}"{{ params.from_net_id }}"
                      {% else %}""{% endif %}
                    },
                    "fromBigipNetwork":{
                        "name": {% if params.use_exist_selfip or params.devices_to.vlan is defined and params.auto_manage %}"toNetwork"
                        {% else %}"{{ params.devices_to.name }}"{% endif %},
                        "vlan":{
                            "path": "{{ params.devices_to.path }}",
                            "create": {% if params.devices_to.interface is defined %}true{% else %}false{% endif %},
                            "modify": false,
                            "selectedValue": "{{ params.devices_to.path }}",
                            "networkVlanValue": ""
                        },
                        "routeDomain":{
                            "id": 0,
                            "create": false
                        },
                        "selfIpConfig":{
                            "create": {% if params.devices_to.interface is defined %}true{% else %}
                            {% if params.use_exist_selfip or (params.devices_to.vlan is defined and params.auto_manage) %}false
                            {% else %}true{% endif %}{% endif %},
                            "modify": false,
                            "autoValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0300::107/120"
                            {% else %}"198.19.96.245/25"{% endif %},
                            "selectedValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0300::107/120"
                            {% else %}""{% endif %},
                            "selfIp": "{{ params.devices_to.self_ip }}",
                            "netmask": "{{ params.devices_to.netmask }}",
                            "floating": false,
                            "HAstaticIpMap": []
                        },
                        "networkBlockId": {% if params.to_net_id is defined %}"{{ params.to_net_id }}"
                        {% else %}""{% endif %}
                   }
                },
                "snatConfiguration":{
                   "clientSnat": "{{ params.snat }}",
                   "snat":{
                      "referredObj": {% if params.snat_ref_id is defined -%}"{{ params.snat_ref_id }}"
                      {% else %}""{% endif %},
                      "ipv4SnatAddresses": {% if params.ip_family == 'ipv4' and params.snat_list is defined -%}
                      {{ params.snat_list | tojson }}{% else %}[]{% endif %},
                      "ipv6SnatAddresses": {% if params.ip_family == 'ipv6' and params.snat_list is defined -%}
                      {{ params.snat_list | tojson }}{% else %}[]{% endif %}
                   }
                },
                "loadBalancing":{
                   "devices": {{ params.devices | tojson }},
                   "monitor":{
                      "fromSystem": "{{ params.monitor }}"
                   }
                },
                "initialIpFamily": "{{ params.ip_family }}",
                "ipFamily": "{{ params.ip_family }}",
                "isAutoManage": {{ params.auto_manage | tojson }},
                "portRemap": {% if params.port_remap is defined %}true{% else %}false{% endif %},
                "httpPortRemapValue": {% if params.port_remap is defined -%}{{ params.port_remap }},{% else %}80,
                {% endif %}
                "serviceDownAction": "{{ params.service_down_action }}",
                "iRuleList": {% if params.rules is defined %}{{ params.rules | tojson }}{% else %}[]{% endif %},
                "managedNetwork":{
                    "serviceType": "L3",
                    "ipFamily": "{{ params.ip_family }}",
                    "isAutoManage": false,{% if params.ip_family == 'ipv4' %}
                    "ipv4": {
                        "serviceType": "L3",
                        "ipFamily": "{{ params.ip_family }}",
                        "serviceSubnet": "{{ params.devices_to.network }}",
                        "serviceIndex": 0,
                        "subnetMask": "255.255.255.0",
                        "toServiceNetwork": "{{ params.devices_to.network }}",
                        "toServiceMask": "{{ params.devices_to.netmask }}",
                        "toServiceSelfIp": "{{ params.devices_to.self_ip }}",
                        "fromServiceNetwork": "{{ params.devices_from.network }}",
                        "fromServiceMask": "{{ params.devices_from.netmask }}",
                        "fromServiceSelfIp": "{{ params.devices_from.self_ip }}"
                    }{% endif %},{% if params.ip_family == 'ipv6' %}
                   "ipv6": {
                        "serviceType": "L3",
                        "ipFamily": "{{ params.ip_family }}",
                        "serviceSubnet": "{{ params.devices_to.network }}",
                        "serviceIndex": 0,
                        "subnetMask": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00",
                        "toServiceNetwork": "{{ params.devices_to.network }}",
                        "toServiceMask": "{{ params.devices_to.netmask }}",
                        "toServiceSelfIp": "{{ params.devices_to.self_ip }}",
                        "fromServiceNetwork": "{{ params.devices_from.network }}",
                        "fromServiceMask": "{{ params.devices_from.netmask }}",
                        "fromServiceSelfIp": "{{ params.devices_from.self_ip }}"
                    },{% endif %}
                   "operation":"RESERVEANDCOMMIT"
                }
             },
             "toVlanNetworkObj":{
                "create": {% if params.devices_from.interface is defined %}false{% else %}
                {% if params.use_exist_selfip or params.devices_from.vlan is defined %}
                false{% else %}true{% endif %}{% endif %},
                "modify": false,
                "networkError": false
             },
             "fromVlanNetworkObj":{
                "create": {% if params.devices_to.interface is defined %}false{% else %}
                {% if params.use_exist_selfip or params.devices_to.vlan is defined %}false{% else %}true{% endif %}{% endif %},
                "modify": false,
                "networkError": false
             },{% if not params.use_exist_selfip and (params.devices_from.interface is defined or params.devices_from.interface is defined) %}
             "toNetworkObj":{
                "name": "{{ params.devices_from.name }}",
                "partition": "Common",
                "strictness": false,
                "vlan":{
                    "create": {% if params.devices_from.interface is defined %}true{% else %}false{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_from.name }}",
                    "path": "{{ params.devices_from.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_from %}"{{ params.devices_from.interface }}"
                    {% else %}[]{% endif %},
                    "tag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from -%}
                    {{ params.devices_from.tag }}{% else %}0{% endif %},
                    "networkInterface": {% if 'interface' in params.devices_from -%}
                    "{{ params.devices_from.interface }}"{% else %}""{% endif %},
                    "networkTag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from -%}
                    {{ params.devices_from.tag }}{% else %}0{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.devices_from.interface is defined %}true{% else %}
                    {% if params.use_exist_selfip %}false{% else %}true{% endif %}{% endif %},
                    "modify": false,
                    "selfIp": "{{ params.devices_from.self_ip }}",
                    "netmask": "{{ params.devices_from.netmask }}",
                    "floating": false,
                    "HAstaticIpMap": []
                },
                "routeDomain":{
                    "id": 0,
                    "create": false
                }
             },
             "fromNetworkObj":{
                "name": "{{ params.devices_to.name }}",
                "partition": "Common",
                "strictness": true,
                "vlan":{
                    "create": {% if params.devices_to.interface is defined %}true{% else %}false{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_to.name }}",
                    "path": "{{ params.devices_to.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_to -%}
                    "{{ params.devices_to.interface }}"{% else %}[]{% endif %},
                    "tag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to -%}
                    {{ params.devices_to.tag }}{% else %}0{% endif %},
                    "networkInterface": {% if 'interface' in params.devices_to -%}
                    "{{ params.devices_to.interface }}"{% else %}""{% endif %},
                    "networkTag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to -%}
                    {{ params.devices_to.tag }}{% else %}0{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.devices_to.interface is defined %}true{% else %}
                    {% if params.use_exist_selfip %}false{% else %}true{% endif %}{% endif %},
                    "modify": false,
                    "selfIp": "{{ params.devices_to.self_ip }}",
                    "netmask": "{{ params.devices_to.netmask }}",
                    "floating": false,
                    "HAstaticIpMap": []
                },
                "routeDomain":{
                    "id": 0,
                    "create": false
                }
             },{% else %}
             "toNetworkObj":{
                "name": "{{ params.devices_from.name }}",
                "partition": "Common",
                "strictness": false,
                "vlan":{
                    "create": {% if params.devices_from.interface is defined %}true{% else %}false{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_from.name }}",
                    "path": "{{ params.devices_from.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_from %}"{{ params.devices_from.interface }}"
                    {% else %}[]{% endif %},
                    "tag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from -%}
                    {{ params.devices_from.tag }}{% else %}0{% endif %},
                    "networkInterface": {% if 'interface' in params.devices_from -%}
                    "{{ params.devices_from.interface }}"{% else %}""{% endif %},
                    "networkTag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from -%}
                    {{ params.devices_from.tag }}{% else %}0{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.devices_from.interface is defined %}true{% else %}
                    {% if params.use_exist_selfip or (params.devices_from.vlan is defined and params.auto_manage) %}
                    false{% else %}true{% endif %}{% endif %},
                    "modify": false,
                    "selfIp": "{{ params.devices_from.self_ip }}",
                    "netmask": "{{ params.devices_from.netmask }}",
                    "floating": false,
                    "HAstaticIpMap": []
                },
                "routeDomain":{
                    "id": 0,
                    "create": false
                }
             },
             "fromNetworkObj":{
                "name": "{{ params.devices_to.name }}",
                "partition": "Common",
                "strictness": true,
                "vlan":{
                    "create": {% if params.devices_to.interface is defined %}true{% else %}false{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_to.name }}",
                    "path": "{{ params.devices_to.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_to -%}
                    "{{ params.devices_to.interface }}"{% else %}[]{% endif %},
                    "tag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to -%}
                    {{ params.devices_to.tag }}{% else %}0{% endif %},
                    "networkInterface": {% if 'interface' in params.devices_to -%}
                    "{{ params.devices_to.interface }}"{% else %}""{% endif %},
                    "networkTag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to -%}
                    {{ params.devices_to.tag }}{% else %}0{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.devices_to.interface is defined %}true{% else %}
                    {% if params.use_exist_selfip or (params.devices_to.vlan is defined and params.auto_manage) %}false
                    {% else %}true{% endif %}{% endif %},
                    "modify": false,
                    "selfIp": "{{ params.devices_to.self_ip }}",
                    "netmask": "{{ params.devices_to.netmask }}",
                    "floating": false,
                    "HAstaticIpMap": []
                },
                "routeDomain":{
                    "id": 0,
                    "create": false
                }
             },{% endif %}
             "vendorInfo":{
                "name": "{{ params.vendor_info }}"
             },
            "name": "{{ params.deployment_name }}",
            "partition": "Common",
            "description": "Type: L3",
            "strictness": false,
            "useTemplate": false,
            "serviceTemplate": "",
            "templateName": "Layer 3 Service",
            "previousVersion": {{ params.sslo_version }},
            "version": {{ params.sslo_version }}{% if params.block_id is defined %},
            "existingBlockId": "{{ params.block_id }}"{% endif %}
          }
       },
       {
          "id":"f5-ssl-orchestrator-service-chain",
          "type":"JSON",
          "value":[]
       },
       {
          "id":"f5-ssl-orchestrator-policy",
          "type":"JSON",
          "value":[]
       }
    ],
    "configurationProcessorReference":{
       "link":"https://localhost/mgmt/shared/iapp/processors/f5-iappslx-ssl-orchestrator-gc"
    },
    "configProcessorTimeoutSeconds": 120,
    "statsProcessorTimeoutSeconds": 60,
    "configProcessorAffinity": {
        "processorPolicy": "LOCAL",
        "affinityProcessorReference": {
            "link": "https://localhost/mgmt/shared/iapp/affinity/local"
        }
    },
    "state":"BINDING",
    "presentationHtmlReference":{
       "link":"https://localhost/iapps/f5-iappslx-ssl-orchestrator/sgc/sgcIndex.html"
    },
    "operation":"CREATE"
 }
 """

modify_new = """
{
    "name": "{{ params.name }}",
    "inputProperties":[
       {
          "id":"f5-ssl-orchestrator-operation-context",
          "type":"JSON",
          "value": {
                "version": {{ params.sslo_version }},
                "partition": "Common",
                "strictness": false,
                "operationType": "{{ params.operation }}",
                "deploymentName": "{{ params.deployment_name }}",
                "deploymentType": "SERVICE"{% if params.dep_ref is defined %},
                "deploymentReference": "{{ params.dep_ref }}"{% endif %}
          }
       },
       {
          "id":"f5-ssl-orchestrator-network",
          "type":"JSON",
          "value": []
       },
       {
          "id":"f5-ssl-orchestrator-service",
          "type":"JSON",
          "value":{
             "customService":{
                "name": "{{ params.deployment_name }}",
                "serviceType": "L3",
                "serviceSpecific":{
                    "name": "{{ params.deployment_name }}"
                },
                "serviceEntrySSLProfile": "{{ params.service_entry_sslprofile }}",
                "serviceReturnSSLProfile": "{{ params.service_return_sslprofile }}",
                "controlChannels": {{ params.control_channels | tojson }},
                "connectionInformation":{
                    "toBigipNetwork":{
                        "name": {% if params.use_exist_selfip or params.devices_from.vlan is defined and params.auto_manage %}"fromNetwork"{% else %}
                        "{{ params.devices_from.name }}"{% endif %},
                        "vlan":{
                            "path": "{{ params.devices_from.path }}",
                            "create": {% if params.devices_from.interface is defined %}false{% else %}false{% endif %},
                            "modify": false,
                            "selectedValue": "{{ params.devices_from.path }}",
                            "networkVlanValue": ""
                        },
                        "routeDomain":{
                            "id":0,
                            "create": false
                        },
                        "selfIpConfig":{
                            "create": {% if params.devices_from.interface is defined %}false{% else %}
                            {% if params.use_exist_selfip or (params.devices_from.vlan is defined and params.auto_manage) %}false
                            {% else %}true{% endif %}{% endif %},
                            "modify": false,
                            "autoValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0300::7/120"
                            {% else %}"198.19.96.7/25"{% endif %},
                            "selectedValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0300::7/120"
                            {% else %}""{% endif %},
                            "selfIp": "{{ params.devices_from.self_ip }}",
                            "netmask": "{{ params.devices_from.netmask }}",
                            "floating": false,
                            "HAstaticIpMap": []
                        },
                      "networkBlockId": {% if params.from_net_id is defined %}"{{ params.from_net_id }}"
                      {% else %}""{% endif %}
                    },
                    "fromBigipNetwork":{
                        "name": {% if params.use_exist_selfip or params.devices_to.vlan is defined and params.auto_manage %}"toNetwork"
                        {% else %}"{{ params.devices_to.name }}"{% endif %},
                        "vlan":{
                            "path": "{{ params.devices_to.path }}",
                            "create": {% if params.devices_to.interface is defined %}false{% else %}false{% endif %},
                            "modify": false,
                            "selectedValue": "{{ params.devices_to.path }}",
                            "networkVlanValue": ""
                        },
                        "routeDomain":{
                            "id": 0,
                            "create": false
                        },
                        "selfIpConfig":{
                            "create": {% if params.devices_to.interface is defined %}false{% else %}
                            {% if params.use_exist_selfip or (params.devices_to.vlan is defined and params.auto_manage) %}false
                            {% else %}false{% endif %}{% endif %},
                            "modify": false,
                            "autoValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0300::107/120"
                            {% else %}"198.19.96.245/25"{% endif %},
                            "selectedValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0300::107/120"
                            {% else %}""{% endif %},
                            "selfIp": "{{ params.devices_to.self_ip }}",
                            "netmask": "{{ params.devices_to.netmask }}",
                            "floating": false,
                            "HAstaticIpMap": []
                        },
                        "networkBlockId": {% if params.to_net_id is defined %}"{{ params.to_net_id }}"
                        {% else %}""{% endif %}
                   }
                },
                "snatConfiguration":{
                   "clientSnat": "{{ params.snat }}",
                   "snat":{
                      "referredObj": {% if params.snat_ref_id is defined -%}"{{ params.snat_ref_id }}"
                      {% else %}""{% endif %},
                      "ipv4SnatAddresses": {% if params.ip_family == 'ipv4' and params.snat_list is defined -%}
                      {{ params.snat_list | tojson }}{% else %}[]{% endif %},
                      "ipv6SnatAddresses": {% if params.ip_family == 'ipv6' and params.snat_list is defined -%}
                      {{ params.snat_list | tojson }}{% else %}[]{% endif %}
                   }
                },
                "loadBalancing":{
                   "devices": {{ params.devices | tojson }},
                   "monitor":{
                      "fromSystem": "{{ params.monitor }}"
                   }
                },
                "initialIpFamily": "{{ params.ip_family }}",
                "ipFamily": "{{ params.ip_family }}",
                "isAutoManage": {{ params.auto_manage | tojson }},
                "portRemap": {% if params.port_remap is defined %}true{% else %}false{% endif %},
                "httpPortRemapValue": {% if params.port_remap is defined -%}{{ params.port_remap }},{% else %}80,
                {% endif %}
                "serviceDownAction": "{{ params.service_down_action }}",
                "iRuleList": {% if params.rules is defined %}{{ params.rules | tojson }}{% else %}[]{% endif %},
                "managedNetwork":{
                    "serviceType": "L3",
                    "ipFamily": "{{ params.ip_family }}",
                    "isAutoManage": false,{% if params.ip_family == 'ipv4' %}
                    "ipv4": {
                        "serviceType": "L3",
                        "ipFamily": "{{ params.ip_family }}",
                        "serviceSubnet": "{{ params.devices_to.network }}",
                        "serviceIndex": 0,
                        "subnetMask": "255.255.255.0",
                        "toServiceNetwork": "{{ params.devices_to.network }}",
                        "toServiceMask": "{{ params.devices_to.netmask }}",
                        "toServiceSelfIp": "{{ params.devices_to.self_ip }}",
                        "fromServiceNetwork": "{{ params.devices_from.network }}",
                        "fromServiceMask": "{{ params.devices_from.netmask }}",
                        "fromServiceSelfIp": "{{ params.devices_from.self_ip }}"
                    }{% endif %},{% if params.ip_family == 'ipv6' %}
                   "ipv6": {
                        "serviceType": "L3",
                        "ipFamily": "{{ params.ip_family }}",
                        "serviceSubnet": "{{ params.devices_to.network }}",
                        "serviceIndex": 0,
                        "subnetMask": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00",
                        "toServiceNetwork": "{{ params.devices_to.network }}",
                        "toServiceMask": "{{ params.devices_to.netmask }}",
                        "toServiceSelfIp": "{{ params.devices_to.self_ip }}",
                        "fromServiceNetwork": "{{ params.devices_from.network }}",
                        "fromServiceMask": "{{ params.devices_from.netmask }}",
                        "fromServiceSelfIp": "{{ params.devices_from.self_ip }}"
                    },{% endif %}
                   "operation":"RESERVEANDCOMMIT"
                }
             },
             "toVlanNetworkObj":{
                "create": {% if params.devices_from.interface is defined %}false{% else %}
                {% if params.use_exist_selfip or params.devices_from.vlan is defined %}
                false{% else %}true{% endif %}{% endif %},
                "modify": false,
                "networkError": false
             },
             "fromVlanNetworkObj":{
                "create": {% if params.devices_to.interface is defined %}false{% else %}
                {% if params.use_exist_selfip or params.devices_to.vlan is defined %}false{% else %}true{% endif %}{% endif %},
                "modify": false,
                "networkError": false
             },{% if not params.use_exist_selfip and (params.devices_from.interface is defined or params.devices_to.interface is defined) %}
             "toNetworkObj":{
                "name": "{{ params.devices_from.name }}",
                "partition": "Common",
                "strictness": false,
                "vlan":{
                    "create": {% if params.devices_from.interface is defined %}false{% else %}false{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_from.name }}",
                    "path": "{{ params.devices_from.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_from %}"{{ params.devices_from.interface }}"
                    {% else %}[]{% endif %},
                    "tag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from -%}
                    {{ params.devices_from.tag }}{% else %}0{% endif %},
                    "networkInterface": {% if 'interface' in params.devices_from -%}
                    "{{ params.devices_from.interface }}"{% else %}""{% endif %},
                    "networkTag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from -%}
                    {{ params.devices_from.tag }}{% else %}0{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.devices_from.interface is defined %}false{% else %}
                    {% if params.use_exist_selfip %}false{% else %}true{% endif %}{% endif %},
                    "modify": false,
                    "selfIp": "{{ params.devices_from.self_ip }}",
                    "netmask": "{{ params.devices_from.netmask }}",
                    "floating": false,
                    "HAstaticIpMap": []
                },
                "routeDomain":{
                    "id": 0,
                    "create": false
                }
             },
             "fromNetworkObj":{
                "name": "{{ params.devices_to.name }}",
                "partition": "Common",
                "strictness": true,
                "vlan":{
                    "create": {% if params.devices_to.interface is defined %}false{% else %}false{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_to.name }}",
                    "path": "{{ params.devices_to.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_to -%}
                    "{{ params.devices_to.interface }}"{% else %}[]{% endif %},
                    "tag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to -%}
                    {{ params.devices_to.tag }}{% else %}0{% endif %},
                    "networkInterface": {% if 'interface' in params.devices_to -%}
                    "{{ params.devices_to.interface }}"{% else %}""{% endif %},
                    "networkTag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to -%}
                    {{ params.devices_to.tag }}{% else %}0{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.devices_to.interface is defined %}false{% else %}
                    {% if params.use_exist_selfip %}false{% else %}false{% endif %}{% endif %},
                    "modify": false,
                    "selfIp": "{{ params.devices_to.self_ip }}",
                    "netmask": "{{ params.devices_to.netmask }}",
                    "floating": false,
                    "HAstaticIpMap": []
                },
                "routeDomain":{
                    "id": 0,
                    "create": false
                }
             },{% else %}
             "toNetworkObj":{
                "name": "{{ params.devices_from.name }}",
                "partition": "Common",
                "strictness": false,
                "vlan":{
                    "create": {% if params.devices_from.interface is defined %}false{% else %}false{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_from.name }}",
                    "path": "{{ params.devices_from.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_from %}"{{ params.devices_from.interface }}"
                    {% else %}[]{% endif %},
                    "tag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from -%}
                    {{ params.devices_from.tag }}{% else %}0{% endif %},
                    "networkInterface": {% if 'interface' in params.devices_from -%}
                    "{{ params.devices_from.interface }}"{% else %}""{% endif %},
                    "networkTag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from -%}
                    {{ params.devices_from.tag }}{% else %}0{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.devices_from.interface is defined %}false{% else %}
                    {% if params.use_exist_selfip or (params.devices_from.vlan is defined and params.auto_manage) %}
                    false{% else %}true{% endif %}{% endif %},
                    "modify": false,
                    "selfIp": "{{ params.devices_from.self_ip }}",
                    "netmask": "{{ params.devices_from.netmask }}",
                    "floating": false,
                    "HAstaticIpMap": []
                },
                "routeDomain":{
                    "id": 0,
                    "create": false
                }
             },
             "fromNetworkObj":{
                "name": "{{ params.devices_to.name }}",
                "partition": "Common",
                "strictness": true,
                "vlan":{
                    "create": {% if params.devices_to.interface is defined %}false{% else %}false{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_to.name }}",
                    "path": "{{ params.devices_to.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_to -%}
                    "{{ params.devices_to.interface }}"{% else %}[]{% endif %},
                    "tag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to -%}
                    {{ params.devices_to.tag }}{% else %}0{% endif %},
                    "networkInterface": {% if 'interface' in params.devices_to -%}
                    "{{ params.devices_to.interface }}"{% else %}""{% endif %},
                    "networkTag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to -%}
                    {{ params.devices_to.tag }}{% else %}0{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.devices_to.interface is defined %}false{% else %}
                    {% if params.use_exist_selfip or (params.devices_to.vlan is defined and params.auto_manage) %}false
                    {% else %}true{% endif %}{% endif %},
                    "modify": false,
                    "selfIp": "{{ params.devices_to.self_ip }}",
                    "netmask": "{{ params.devices_to.netmask }}",
                    "floating": false,
                    "HAstaticIpMap": []
                },
                "routeDomain":{
                    "id": 0,
                    "create": false
                }
             },{% endif %}
             "vendorInfo":{
                "name": "{{ params.vendor_info }}"
             },
            "name": "{{ params.deployment_name }}",
            "partition": "Common",
            "description": "Type: L3",
            "strictness": false,
            "useTemplate": false,
            "serviceTemplate": "",
            "templateName": "Layer 3 Service",
            "previousVersion": {{ params.sslo_version }},
            "version": {{ params.sslo_version }}{% if params.block_id is defined %},
            "existingBlockId": "{{ params.block_id }}"{% endif %}
          }
       },
       {
          "id":"f5-ssl-orchestrator-service-chain",
          "type":"JSON",
          "value":[]
       },
       {
          "id":"f5-ssl-orchestrator-policy",
          "type":"JSON",
          "value":[]
       }
    ],
    "configurationProcessorReference":{
       "link":"https://localhost/mgmt/shared/iapp/processors/f5-iappslx-ssl-orchestrator-gc"
    },
    "configProcessorTimeoutSeconds": 120,
    "statsProcessorTimeoutSeconds": 60,
    "configProcessorAffinity": {
        "processorPolicy": "LOCAL",
        "affinityProcessorReference": {
            "link": "https://localhost/mgmt/shared/iapp/affinity/local"
        }
    },
    "state":"BINDING",
    "presentationHtmlReference":{
       "link":"https://localhost/iapps/f5-iappslx-ssl-orchestrator/sgc/sgcIndex.html"
    },
    "operation":"CREATE"
 }
 """
