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
                    "partition": "Common",
                    "name": "{{ params.deployment_name }}",
                    "previousVersion": {{ params.sslo_version }},
                    "version": {{ params.sslo_version }},
                    "existingBlockId": "{{ params.block_id }}"
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
          "value": [{%  if params.devices_to is defined  and 'interface' in params.devices_to %}
            {
                "name": "{{ params.devices_to.name }}",
                "partition": "Common",
                "strictness": false,
                "create": true,
                "vlan":{
                    "name": "{{ params.devices_to.name }}",
                    "path": "{{ params.devices_to.path }}",
                    "create": true,
                    "modify": false,
                    "networkError": false,
                    "interface":[
                        "{{ params.devices_to.interface }}"
                    ],{% if params.devices_to.tag is defined %}
                    "tag": {{ params.devices_to.tag }},
                    "networkTag": {{ params.devices_to.tag }},{% endif %}
                    "networkInterface": "{{ params.devices_to.interface }}"
                },
                "selfIpConfig":{
                    "create": true,
                    "modify": false,
                    "selfIp": "",
                    "netmask": "",
                    "floating": false,
                    "HAstaticIpMap": []
                },
                "routeDomain":{
                    "id": 0,
                    "create": false
                },
                "existingBlockId": ""
             }{% if params.devices_from is defined  and 'interface' in params.devices_from %},{% endif %}{% endif %}
             {% if params.devices_from is defined  and 'interface' in params.devices_from %}
                {
                    "name": "{{ params.devices_from.name }}",
                    "partition": "Common",
                    "strictness": false,
                    "create": true,
                    "vlan":{
                        "name": "{{ params.devices_from.name }}",
                        "path": "{{ params.devices_from.path }}",
                        "create": true,
                        "modify": false,
                        "networkError": false,
                        "interface":[
                            "{{ params.devices_from.interface }}"
                        ],{% if params.devices_from.tag is defined %}
                        "tag": {{ params.devices_from.tag }},
                        "networkTag": {{ params.devices_from.tag }},{% endif %}
                        "networkInterface": "{{ params.devices_from.interface }}"
                },
                "selfIpConfig":{
                    "create": true,
                    "modify": false,
                    "selfIp": "",
                    "netmask": "",
                    "floating": false,
                    "HAstaticIpMap": []
                },
                "routeDomain":{
                    "id": 0,
                    "create": false
                },
                "existingBlockId":""
             }{% endif %}
          ]
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
                "connectionInformation":{
                    "fromBigipNetwork":{
                        "name": "{{ params.devices_to.name }}",
                        "vlan":{
                            "path": "{{ params.devices_to.path }}",
                            "create": {% if 'vlan' in params.devices_to %}false{% else %}true{% endif %},
                            "selectedValue": {% if 'vlan' in params.devices_to %}"{{ params.devices_to.path }}"{% else %}""{% endif %},
                            "modify": false,
                            "networkVlanValue": ""
                        },
                        "routeDomain":{
                            "id":0,
                            "create": false
                        },
                        "selfIpConfig":{
                            "create": true,
                            "modify": false,
                            "autoValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0300::7/120"
                            {% else %}"198.19.64.7/25"{% endif %},
                            "selectedValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0300::7/120"
                            {% else %}""{% endif %},
                            "selfIp": "{{ params.devices_to.self_ip }}",
                            "netmask": "{{ params.devices_to.netmask }}",
                            "floating": false,
                            "HAstaticIpMap": []
                        },
                      "networkBlockId": {% if params.from_net_id is defined %}"{{ params.from_net_id }}"
                      {% else %}""{% endif %}
                    },
                    "toBigipNetwork":{
                        "name": "{{ params.devices_from.name }}",
                        "vlan":{
                            "path": "{{ params.devices_from.path }}",
                            "create": {% if 'vlan' in params.devices_from %}false{% else %}true{% endif %},
                            "modify": false,
                            "selectedValue": {% if 'vlan' in params.devices_from %}"{{ params.devices_from.path }}"{% else %}""{% endif %},
                            "networkVlanValue": ""
                        },
                        "routeDomain":{
                            "id": 0,
                            "create": false
                        },
                        "selfIpConfig":{
                            "create": true,
                            "modify": false,
                            "autoValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0300::107/120"
                            {% else %}"198.19.64.245/25"{% endif %},
                            "selectedValue": {% if params.ip_family == 'ipv6' %}"2001:0200:0:0300::107/120"
                            {% else %}""{% endif %},
                            "selfIp": "{{ params.devices_from.self_ip }}",
                            "netmask": "{{ params.devices_from.netmask }}",
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
                      "referredObj": {% if params.snat_ref_id is defined %}"{{ params.snat_ref_id }}"
                      {% else %}""{% endif %},
                      "ipv4SnatAddresses": {% if params.ip_family == 'ipv4' and params.snat_list is defined %}
                      {{ params.snat_list | tojson }}{% else %}[]{% endif %},
                      "ipv6SnatAddresses": {% if params.ip_family == 'ipv6' and params.snat_list is defined %}
                      {{ params.snat_list | tojson }}{% else %}[]{% endif %}
                   }
                },
                "loadBalancing":{
                   "devices": {{ params.devices | tojson }},
                   "monitor":{
                      "fromSystem": "{{ params.monitor }}"
                   }
                },
                "initialIpFamily": "ipv4",
                "ipFamily": "{{ params.ip_family }}",
                "isAutoManage": true,
                "portRemap": {% if params.port_remap is defined %}true{% else %}false{% endif %},
                "httpPortRemapValue": {% if params.port_remap is defined %}{{ params.port_remap }}
                {% else %}80{% endif %},
                "serviceDownAction": "{{ params.service_down_action }}",
                "iRuleList": {% if params.rules is defined %}{{ params.rules | tojson }}{% else %}[]{% endif %},
                "managedNetwork":{
                    "serviceType": "L3",
                    "ipFamily": "ipv4",
                    "isAutoManage": true,
                    "ipv4": {% if params.ip_family == 'ipv4' %}{
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
                    }{% else %}{}{% endif %},
                   "ipv6": {% if params.ip_family == 'ipv6' %}{
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
                    }{% else %}{}{% endif %},
                   "operation":"RESERVEANDCOMMIT"
                }
             },
             "fromVlanNetworkObj":{
                "create": true,
                "modify": false,
                "networkError": false
             },
             "fromNetworkObj":{
                "name": "{{ params.devices_to.name }}",
                "create": true,
                "partition": "Common",
                "strictness": false,
                "vlan":{
                    "create": {% if 'vlan' in params.devices_to %}false{% else %}true{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_to.name }}",
                    "path": "{{ params.devices_to.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_to %}["{{ params.devices_to.interface }}"]
                    {% else %}[]{% endif %},
                    "tag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to %}
                    {{ params.devices_to.tag }}{% else %}0{% endif %},
                    "networkInterface": {% if 'interface' in params.devices_to %}
                    "{{ params.devices_to.interface }}"{% else %}""{% endif %},
                    "networkTag": {% if 'interface' in params.devices_to and 'tag' in params.devices_to %}
                    {{ params.devices_to.tag }}{% else %}0{% endif %}
                },
                "selfIpConfig":{
                    "create": true,
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
             "toVlanNetworkObj":{
                "create": true,
                "modify": false,
                "networkError": false
             },
             "toNetworkObj":{
                "name": "{{ params.devices_from.name }}",
                "create": {% if 'vlan' in params.devices_from %}false{% else %}true{% endif %},
                "partition": "Common",
                "strictness": true,
                "vlan":{
                    "create": {% if 'vlan' in params.devices_from %}false{% else %}true{% endif %},
                    "modify": false,
                    "name": "{{ params.devices_from.name }}",
                    "path": "{{ params.devices_from.path }}",
                    "networkError": false,
                    "interface": {% if 'interface' in params.devices_from %}
                    ["{{ params.devices_from.interface }}"]{% else %}[]{% endif %},
                    "tag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from %}
                    {{ params.devices_from.tag }}{% else %}0{% endif %},
                    "networkInterface": {% if 'interface' in params.devices_from %}
                    "{{ params.devices_from.interface }}"{% else %}""{% endif %},
                    "networkTag": {% if 'interface' in params.devices_from and 'tag' in params.devices_from %}
                    {{ params.devices_from.tag }}{% else %}0{% endif %}
                },
                "selfIpConfig":{
                    "create": true,
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
             "vendorInfo":{
                "name":"Generic Inline Layer 3"
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
