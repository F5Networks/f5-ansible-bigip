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
                    "interface":["{{ params.devices_to.interface }}"],
                    "networkInterface": "{{ params.devices_to.interface }}",
                    "tag": {% if 'tag' in params.devices_to -%}{{ params.devices_to.tag }}{% else %}0{% endif %},
                    "networkTag": {% if 'tag' in params.devices_to -%}{{ params.devices_to.tag }}{% else %}0{% endif %}{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.auto_manage %}false{% else %}true{% endif %},
                    "modify": false,
                    "selfIp": {% if params.auto_manage %}""{% elif params.devices_to.self_ip is defined %}
                    "{{ params.devices_to.self_ip }}"{% else %}""{% endif %},
                    "netmask": {% if params.auto_manage %}""{% elif params.devices_to.netmask is defined %}
                    "{{ params.devices_to.netmask }}"{% else %}""{% endif %},
                    "floating": false,
                    "HAstaticIpMap": []
                },
                "routeDomain":{
                    "id": 0,
                    "create": false
                },
                "existingBlockId": ""
             }{% if params.devices_from.vlan is not defined or not params.auto_manage -%},{% endif %}{% endif %}
             {% if params.devices_from.vlan is not defined or not params.auto_manage -%}
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
                        "interface":["{{ params.devices_from.interface }}"],
                        "networkInterface": "{{ params.devices_from.interface }}",
                        "tag": {% if 'tag' in params.devices_from -%}{{ params.devices_from.tag }}{% else %}0{% endif %},
                        "networkTag": {% if 'tag' in params.devices_from -%}{{ params.devices_from.tag }}{% else %}0{% endif %}{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.auto_manage %}false{% else %}true{% endif %},
                    "modify": false,
                    "selfIp": {% if params.auto_manage %}""{% elif params.devices_from.self_ip is defined %}
                    "{{ params.devices_from.self_ip }}"{% else %}""{% endif %},
                    "netmask": {% if params.auto_manage %}""{% elif params.devices_from.netmask is defined %}
                    "{{ params.devices_from.netmask }}"{% else %}""{% endif %},
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
                "serviceType": "awaf-off-box",
                "serviceSpecific":{
                    "name": "{{ params.deployment_name }}",
                    "proxyType": "Transparent",
                    "httpProfile": "{{ params.http_profile }}",
                    "description": ""
                },
                "connectionInformation":{
                    "fromBigipNetwork":{
                        "name": {% if params.use_exist_selfip or params.devices_to.vlan is defined %}"toNetwork"{% else %}
                        "{{ params.devices_to.name }}"{% endif %},
                        "vlan":{
                            "path": "{{ params.devices_to.path }}",
                            "create": {% if params.devices_to.interface is defined %}true{% else %}false{% endif %},
                            "modify": false,
                            "selectedValue": "{{ params.devices_to.path }}",
                            "networkVlanValue": ""
                        },
                        "routeDomain":{
                            "id":0,
                            "create": false
                        },
                        "selfIpConfig":{
                            "create": {% if params.devices_to.interface is defined %}true{% else %}
                            {% if params.use_exist_selfip or (params.devices_to.vlan is defined and params.auto_manage) %}false
                            {% else %}true{% endif %}{% endif %},
                            "modify": false,
                            "autoValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0500::a/120"
                            {% elif params.devices_to.self_ip is defined %}"{{ params.devices_to.self_ip }}/25"
                            {% else %}"198.19.128.7/25"{% endif %},
                            "selectedValue": {% if params.use_exist_selfip and params.devices_to.self_ip is defined %}"{{ params.devices_to.self_ip }}"
                            {% elif params.ip_family == 'ipv6' %}"2001:0200:0:0500::a/120"
                            {% else %}""{% endif %},
                            "selfIp": {% if params.devices_to.self_ip is defined %}"{{ params.devices_to.self_ip }}"
                            {% else %}"198.19.128.7"{% endif %},
                            "netmask": {% if params.devices_to.netmask is defined %}"{{ params.devices_to.netmask }}"
                            {% else %}"255.255.255.128"{% endif %},
                            "floating": false,
                            "HAstaticIpMap": []
                        },
                      "networkBlockId": {% if params.from_net_id is defined %}"{{ params.from_net_id }}"
                      {% else %}""{% endif %}
                    },
                    "toBigipNetwork":{
                        "name": {% if params.use_exist_selfip or params.devices_from.vlan is defined %}"fromNetwork"
                        {% else %}"{{ params.devices_from.name }}"{% endif %},
                        "vlan":{
                            "path": "{{ params.devices_from.path }}",
                            "create": {% if params.devices_from.interface is defined %}true{% else %}false{% endif %},
                            "modify": false,
                            "selectedValue": "{{ params.devices_from.path }}",
                            "networkVlanValue": ""
                        },
                        "routeDomain":{
                            "id": 0,
                            "create": false
                        },
                        "selfIpConfig":{
                            "create": {% if params.devices_from.interface is defined %}true{% else %}
                            {% if params.use_exist_selfip or (params.devices_from.vlan is defined and params.auto_manage) %}false
                            {% else %}true{% endif %}{% endif %},
                            "modify": false,
                            "autoValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0500::8a/120"
                            {% elif params.devices_from.self_ip is defined %}"{{ params.devices_from.self_ip }}/25"
                            {% else %}"198.19.128.245/25"{% endif %},
                            "selectedValue": {% if params.use_exist_selfip and params.devices_from.self_ip is defined %}"{{ params.devices_from.self_ip }}"
                            {% elif params.ip_family == 'ipv6' %}"2001:0200:0:0500::8a/120"
                            {% else %}""{% endif %},
                            "selfIp": {% if params.devices_from.self_ip is defined %}"{{ params.devices_from.self_ip }}"
                            {% else %}"198.19.128.245"{% endif %},
                            "netmask": {% if params.devices_from.netmask is defined %}"{{ params.devices_from.netmask }}"
                            {% else %}"255.255.255.128"{% endif %},
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
                {% if params.sslo_version >= 14.0 -%}
                {% set dpp = params.default_persistence_profile if params.default_persistence_profile else '' -%}
                "defaultPersistenceProfile": "{{ dpp }}",
                {% endif -%}
                "serviceEntrySSLProfile": "{{ params.service_entry_sslprofile }}",
                "serviceReturnSSLProfile": "{{ params.service_return_sslprofile }}",
                "controlChannels": {{ params.control_channels | tojson }},
                "httpPortRemapValue": {% if params.port_remap is defined -%}{{ params.port_remap }},{% else %}80,
                {% endif %}
                "serviceDownAction": "{{ params.service_down_action }}",
                "iRuleList": {% if params.rules is defined %}{{ params.rules | tojson }}{% else %}[]{% endif %},
                {% if params.sslo_version >= 13.0 -%}
                {% set egress = params.rules_egress if params.rules_egress is defined else [] -%}
                "iRuleListEgress": {{ egress | tojson }},
                {% endif %}
                "managedNetwork":{
                    "serviceType": "awaf-off-box",
                    "ipFamily": "{{ params.ip_family }}",
                    "isAutoManage": {{ params.auto_manage | tojson }},{% if params.ip_family == 'ipv4' %}
                    {% if params.auto_manage and params.devices_to.self_ip is not defined %}"ipv4": {
                        "serviceType": "awaf-off-box",
                        "ipFamily": "{{ params.ip_family }}",
                        "serviceSubnet": "198.19.128.0",
                        "serviceIndex": 0,
                        "subnetMask": "255.255.255.0",
                        "toServiceNetwork": "198.19.128.0",
                        "toServiceMask": "255.255.255.128",
                        "toServiceSelfIp": "198.19.128.7",
                        "fromServiceNetwork": "198.19.128.128",
                        "fromServiceMask": "255.255.255.128",
                        "fromServiceSelfIp": "198.19.128.245"
                    }{% else %}"ipv4": {
                        "serviceType": "awaf-off-box",
                        "ipFamily": "{{ params.ip_family }}",
                        "serviceSubnet": {% if params.devices_to.network is defined %}"{{ params.devices_to.network }}"{% else %}"198.19.128.0"{% endif %},
                        "serviceIndex": 0,
                        "subnetMask": "255.255.255.0",
                        "toServiceNetwork":
                        {% if params.devices_to.network is defined %}"{{ params.devices_to.network }}"{% else %}"198.19.128.0"{% endif %},
                        "toServiceMask":
                        {% if params.devices_to.netmask is defined %}"{{ params.devices_to.netmask }}"{% else %}"255.255.255.128"{% endif %},
                        "toServiceSelfIp":
                        {% if params.devices_to.self_ip is defined %}"{{ params.devices_to.self_ip }}"{% else %}"198.19.128.7"{% endif %},
                        "fromServiceNetwork":
                        {% if params.devices_from.network is defined %}"{{ params.devices_from.network }}"{% else %}"198.19.128.128"{% endif %},
                        "fromServiceMask":
                        {% if params.devices_from.netmask is defined %}"{{ params.devices_from.netmask }}"{% else %}"255.255.255.128"{% endif %},
                        "fromServiceSelfIp":
                        {% if params.devices_from.self_ip is defined %}"{{ params.devices_from.self_ip }}"{% else %}"198.19.128.245"{% endif %}
                    }{% endif %}{% endif %},{% if params.ip_family == 'ipv6' %}
                   "ipv6": {
                        "serviceType": "awaf-off-box",
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
             "fromVlanNetworkObj":{
                "create": {% if params.devices_to.interface is defined %}false{% else %}{% if params.use_exist_selfip or params.devices_to.vlan is defined %}
                false{% else %}true{% endif %}{% endif %},
                "modify": false,
                "networkError": false
             },
             "toVlanNetworkObj":{
                "create": {% if params.devices_from.interface is defined %}false{% else %}
                {% if params.use_exist_selfip or params.devices_from.vlan is defined %}false{% else %}true{% endif %}{% endif %},
                "modify": false,
                "networkError": false
             },{% if not params.use_exist_selfip and (params.devices_from.interface is defined or params.devices_to.interface is defined) %}
             "fromNetworkObj":{
                "name": "{{ params.devices_to.name }}",
                "partition": "Common",
                "strictness": false,
                "vlan":{
                    "create": {% if params.devices_to.interface is defined %}true{% else %}false{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_to.name }}",
                    "path": "{{ params.devices_to.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_to %}"{{ params.devices_to.interface }}"
                    {% else %}[]{% endif %},
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
             },
             "toNetworkObj":{
                "name": "{{ params.devices_from.name }}",
                "partition": "Common",
                "strictness": true,
                "vlan":{
                    "create": {% if params.devices_from.interface is defined %}true{% else %}false{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_from.name }}",
                    "path": "{{ params.devices_from.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_from -%}
                    "{{ params.devices_from.interface }}"{% else %}[]{% endif %},
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
             },{% elif not params.use_exist_selfip %}
             "fromNetworkObj":{
                "name": "{{ params.devices_to.name }}",
                "partition": "Common",
                "strictness": false,
                "vlan":{
                    "create": {% if params.devices_to.interface is defined %}true{% else %}false{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_to.name }}",
                    "path": "{{ params.devices_to.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_to %}"{{ params.devices_to.interface }}"
                    {% else %}[]{% endif %},
                    "tag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to -%}
                    {{ params.devices_to.tag }}{% else %}0{% endif %},
                    "networkInterface": {% if 'interface' in params.devices_to -%}
                    "{{ params.devices_to.interface }}"{% else %}""{% endif %},
                    "networkTag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to -%}
                    {{ params.devices_to.tag }}{% else %}0{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.devices_to.interface is defined %}true{% else %}
                    {% if params.use_exist_selfip or (params.devices_to.vlan is defined and params.auto_manage) %}
                    false{% else %}true{% endif %}{% endif %},
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
             },
             "toNetworkObj":{
                "name": "{{ params.devices_from.name }}",
                "partition": "Common",
                "strictness": true,
                "vlan":{
                    "create": {% if params.devices_from.interface is defined %}true{% else %}false{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_from.name }}",
                    "path": "{{ params.devices_from.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_from -%}
                    "{{ params.devices_from.interface }}"{% else %}[]{% endif %},
                    "tag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from -%}
                    {{ params.devices_from.tag }}{% else %}0{% endif %},
                    "networkInterface": {% if 'interface' in params.devices_from -%}
                    "{{ params.devices_from.interface }}"{% else %}""{% endif %},
                    "networkTag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from -%}
                    {{ params.devices_from.tag }}{% else %}0{% endif %}
                },
                "selfIpConfig":{
                    "create": {% if params.devices_from.interface is defined %}true{% else %}
                    {% if params.use_exist_selfip or (params.devices_from.vlan is defined and params.auto_manage) %}false
                    {% else %}true{% endif %}{% endif %},
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
             },{% endif %}
             "vendorInfo":{
                "name": "F5 Advanced WAF (Off-Box)"
             },
            "name": "{{ params.deployment_name }}",
            "partition": "Common",
            "description": "Type: AWAF Off-Box",
            "strictness": false,
            "useTemplate": false,
            "serviceTemplate": "",
            "templateName": "AWAF Off-Box Service",
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
    "operation":"{{ params.operation }}"
 }
"""
