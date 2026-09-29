create = """
{
    "name": "{{ params.name }}",
    "inputProperties":[
         {
            "id": "f5-ssl-orchestrator-operation-context",
            "type": "JSON",
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
             "value":{% if params.networks is defined %}[{% for network in params.networks %}
                    {
                    "partition": "Common",
                    "strictness": false,
                    "name": "{{ network.name }}",
                    "previousVersion": {{ params.sslo_version }},
                    "version": {{ params.sslo_version }},
                    "vlan":{
                        "create": true,
                        "path": "{{ network.path }}",
                        "interface":[
                           "{{ network.interface }}"
                        ],
                        "name": "{{ network.name }}"{%- if network.tag is defined and network.tag != none %},
                        "tag": "{{ network.tag }}"{%- endif %}
                    },
                    "selfIpConfig": {
                        "selfIp": "",
                        "netmask": "",
                        "floating": false,
                        "HAstaticIpMap":[
                            {
                                "deviceMgmtIp":"",
                                "selfIp":""
                            }
                        ]
                    },
                    "routeDomain":{
                        "create": false,
                        "id": 0,
                        "path": ""
                    }{% if network.block_id is defined %},
                    "existingBlockId": "{{ network.block_id }}"{% endif %}
                }{% if not loop.last %},{% endif %}{% endfor %}]
            {% else %}[]{% endif %}
         },
         {
             "id":"f5-ssl-orchestrator-service",
             "type":"JSON",
             "value":{
                 "strictness": false,
                 "customService":{
                    "name": "{{ params.deployment_name }}",
                     "serviceType": "L2",
                     "serviceSpecific":{
                         "unitIdMap": [],
                         "description": "",
                         "name": "{{ params.deployment_name }}"
                     },
                     "connectionInformation":{
                         "interfaces": {% if params.interfaces is defined %}[{% for intf in params.interfaces %}
                            {
                                "fromBigipVlan": {
                                    "path": "{{ intf.from_vlan.path }}",
                                    "create": {{ intf.from_vlan.create | tojson }},{% if intf.from_vlan.interface is defined %}
                                    "interface": ["{{ intf.from_vlan.interface }}"],{% endif %}
                                    {% if intf.from_vlan.tag is defined and intf.from_vlan.tag != none -%}
                                    "tag": "{{ intf.from_vlan.tag }}",{% endif %}
                                    "name": "{{ intf.from_vlan.name }}",
                                    "networkBlockId": {% if intf.from_vlan.block_id is defined -%}
                                    "{{ intf.from_vlan.block_id }}"{% else %}""{% endif %}
                                },
                                "toBigipVlan":{
                                    "path": "{{ intf.to_vlan.path }}",
                                    "create": {{ intf.to_vlan.create | tojson }},
                                    {% if intf.to_vlan.interface is defined -%}
                                    "interface": ["{{ intf.to_vlan.interface }}"],{% endif %}
                                    {% if intf.to_vlan.tag is defined and intf.to_vlan.tag != none -%}
                                    "tag": "{{ intf.to_vlan.tag }}",{% endif %}
                                    "name": "{{ intf.to_vlan.name }}",
                                    "networkBlockId": {% if intf.to_vlan.block_id is defined -%}
                                    "{{ intf.to_vlan.block_id }}"{% else %}""{% endif %}
                                }
                            }
                        {% if not loop.last %},{% endif %}{% endfor %}]
                        {% else %}[]{% endif %}
                     },
                     "loadBalancing":{
                        "devices": {% if params.devices_ips is defined %}[{% for device in params.devices_ips %}{
                           "ratio": {% if device.ratio is defined and device.ratio != none -%}
                           "{{ device.ratio }}"{% else %}"1"{% endif %},
                           "port": "0",
                           "ip": {{ device.ip | tojson }}
                        }{% if not loop.last %},{% endif %}{% endfor %}]{% else %}[]{% endif %},
                         "monitor":{
                             "fromSystem": "{{ params.monitor }}"
                         }
                     },
                     "portRemap": {% if params.port_remap %}true{% else %}false{% endif %},
                     "httpPortRemapValue": {% if params.port_remap -%}{{ params.port_remap }},{% else %}80,
                      {% endif %}
                     "serviceDownAction": "{{ params.service_down_action }}",
                     "iRuleReference":"",{% if params.sslo_version >= 14 %}
                     "mode": "{{ params.mode }}",{% endif %}
                     "iRuleList":{% if params.rules is defined %}{{ params.rules | tojson }}{% else %}[]{% endif %},{% if params.sslo_version >= 13 %}
                     "iRuleListEgress":{% if params.rules_egress is defined %}{{ params.rules_egress | tojson }}{% else %}[]{% endif %},{% endif %}
                     {% if params.sslo_version >= 14 %}
                     "defaultPersistenceProfile": "{% if params.default_persistence_profile %}{{ params.default_persistence_profile }}{% endif %}",{% endif %}
                     "managedNetwork":{
                         "serviceType": "L2",
                         "ipFamily": "both",
                         "ipv4":{
                             "serviceType": "L2",
                             "ipFamily": "ipv4",
                             "serviceSubnet": "{{ params.service_subnet.ipv4 }}",
                             "serviceIndex": {{ params.service_index | default(0) }},
                             "subnetMask": "255.255.255.0"
                         },
                         "ipv6":{
                             "serviceType": "L2",
                             "ipFamily": "ipv6",
                             "serviceSubnet": "{{ params.service_subnet.ipv6 }}",
                             "serviceIndex": {{ params.service_index | default(0) }},
                             "subnetMask": "ffff:ffff:ffff:ffff::"
                         },
                         "operation":"RESERVEANDCOMMIT"
                     }
                 },
                 "vendorInfo":{
                    "name": "{{ params.vendor_info }}"
                 },
                 "modifiedNetworkObjects": [],
                 "removedNetworks": [],
                 "networkObjects": {% if params.networks is defined %}[{% for network in params.networks %}
                    {
                        "partition": "Common",
                        "strictness": false,
                        "name": "{{ network.name }}",
                        "previousVersion": {{ params.sslo_version }},
                        "version": {{ params.sslo_version }},
                        "vlan":{
                            "create": true,
                            "path": "{{ network.path }}",
                            "interface":[
                                "{{ network.interface }}"
                            ],
                            "name": "{{ network.name }}"{%- if network.tag is defined and network.tag != none %},
                            "tag": "{{ network.tag }}"{%- endif %}

                        },
                        "selfIpConfig":{
                            "selfIp": "",
                            "netmask": "",
                            "floating": false,
                            "HAstaticIpMap":[
                                {
                                "deviceMgmtIp": "",
                                "selfIp": ""
                                }
                            ]
                        },
                        "routeDomain":{
                            "create": false,
                            "id": 0,
                            "path": ""
                        }
                    }{% if not loop.last %},{% endif %}{% endfor %}]{% else %}[]{% endif %},
                 "fromToVlan": {% if params.interfaces is defined %}[{% for intf in params.interfaces %}
                    {
                        "fromBigipVlan": {
                            "create": {{ intf.from_vlan.create | tojson }},
                            "path": "{{ intf.from_vlan.path }}",
                            {% if intf.from_vlan.interface is defined -%}"interface": ["{{ intf.from_vlan.interface }}"],{% endif %}
                            {% if intf.from_vlan.tag is defined and intf.from_vlan.tag != none -%}"tag": "{{ intf.from_vlan.tag }}",{% endif %}
                            "name": "{{ intf.from_vlan.name }}"
                        },
                        "toBigipVlan": {
                            "create": {{ intf.to_vlan.create | tojson }},
                            "path": "{{ intf.to_vlan.path }}",
                            {% if intf.to_vlan.interface is defined -%}"interface": ["{{ intf.to_vlan.interface }}"],{% endif %}
                            {% if intf.to_vlan.tag is defined and intf.to_vlan.tag != none -%}"tag": "{{ intf.to_vlan.tag }}",{% endif %}
                            "name": "{{ intf.to_vlan.name }}"
                        }
                    }{% if not loop.last %},{% endif %}{% endfor %}]{% else %}[]{% endif %},
                 "fromVlan": {% if params.interfaces is defined and params.interfaces|length > 0 %}{
                    "fromBigipVlan": {
                        "create": {{ params.interfaces[0].from_vlan.create | tojson }},
                        "path": "{{ params.interfaces[0].from_vlan.path }}",
                        {% if params.interfaces[0].from_vlan.interface is defined -%}
                        "interface": ["{{ params.interfaces[0].from_vlan.interface }}"],{% endif %}
                        {% if params.interfaces[0].from_vlan.tag is defined
                            and params.interfaces[0].from_vlan.tag != none -%}
                        "tag": "{{ params.interfaces[0].from_vlan.tag }}",{% endif %}
                        "name": "{{ params.interfaces[0].from_vlan.name }}"
                    },
                    "toBigipVlan": {
                        "create": {{ params.interfaces[0].to_vlan.create | tojson }},
                        "path": "{{ params.interfaces[0].to_vlan.path }}",
                        {% if params.interfaces[0].to_vlan.interface is defined -%}
                        "interface": ["{{ params.interfaces[0].to_vlan.interface }}"],{% endif %}
                        {% if params.interfaces[0].to_vlan.tag is defined
                            and params.interfaces[0].to_vlan.tag != none -%}
                        "tag": "{{ params.interfaces[0].to_vlan.tag }}",{% endif %}
                        "name": "{{ params.interfaces[0].to_vlan.name }}"
                    }
                 }{% else %}{}{% endif %},
                 "name": "{{ params.deployment_name }}",
                 "description": "Type: L2",
                 "useTemplate": false,
                 "serviceTemplate": "",
                 "partition": "Common",
                 "advancedMode": "off",
                 "iRulesSelected": {% if params.rules is defined %}{{ params.rules | tojson }}
                 {% else %}[]{% endif %}{% if params.sslo_version >= 13 %},
                 "iRulesSelectedEgress": {% if params.rules_egress is defined %}{{ params.rules_egress | tojson }}
                 {% else %}[]{% endif %}{% endif %}{% if params.block_id is defined %},
                 "existingBlockId": "{{ params.block_id }}"{% endif %}
             }
         },
         {
             "id": "f5-ssl-orchestrator-service-chain",
             "type": "JSON",
             "value": []
         },
         {
             "id": "f5-ssl-orchestrator-policy",
             "type": "JSON",
             "value": []
         }
     ],
     "dataProperties":[],
     "configurationProcessorReference": {
         "link": "https://localhost/mgmt/shared/iapp/processors/f5-iappslx-ssl-orchestrator-gc"
     },
     "configProcessorTimeoutSeconds": 120,
     "statsProcessorTimeoutSeconds": 60,
     "configProcessorAffinity": {
         "processorPolicy": "LOCAL",
         "affinityProcessorReference": {
            "link": "https://localhost/mgmt/shared/iapp/affinity/local"
         }
     },
     "state": "BINDING",
     "presentationHtmlReference": {
         "link": "https://localhost/iapps/f5-iappslx-ssl-orchestrator/sgc/sgcIndex.html"
     }
}
"""

modify = """
{
    "name": "{{ params.name }}",
    "inputProperties":[
         {
            "id": "f5-ssl-orchestrator-operation-context",
            "type": "JSON",
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
             "value":{% if params.networks is defined %}[{% for network in params.networks %}
                    {
                    "partition": "Common",
                    "strictness": false,
                    "name": "{{ network.name }}",
                    "previousVersion": {{ params.sslo_version }},
                    "version": {{ params.sslo_version }},
                    "vlan":{
                        "create": true,
                        "path": "{{ network.path }}",
                        "interface":[
                           "{{ network.interface }}"
                        ],
                        "name": "{{ network.name }}"{% if network.tag is defined and network.tag != none %},
                        "tag": "{{ network.tag }}"{%- endif %}
                    },
                    "selfIpConfig": {
                        "selfIp": "",
                        "netmask": "",
                        "floating": false,
                        "HAstaticIpMap":[
                            {
                                "deviceMgmtIp":"",
                                "selfIp":""
                            }
                        ]
                    },
                    "routeDomain":{
                        "create": false,
                        "id": 0,
                        "path": ""
                    }{% if network.block_id is defined %},
                    "existingBlockId": "{{ network.block_id }}"{% endif %}
                }{% if not loop.last %},{% endif %}{% endfor %}]
            {% else %}[]{% endif %}
         },
         {
             "id":"f5-ssl-orchestrator-service",
             "type":"JSON",
             "value":{
                 "strictness": false,
                 "customService":{
                    "name": "{{ params.deployment_name }}",
                     "serviceType": "L2",
                     "serviceSpecific":{
                         "unitIdMap": [],
                         "description": "",
                         "name": "{{ params.deployment_name }}"
                     },
                     "connectionInformation":{
                         "interfaces": {% if params.interfaces is defined %}[{% for intf in params.interfaces %}
                            {
                                "fromBigipVlan": {
                                    "path": "{{ intf.from_vlan.path }}",
                                    "create": {{ intf.from_vlan.create | tojson }},
                                    {% if intf.from_vlan.interface is defined -%}
                                    "interface": ["{{ intf.from_vlan.interface }}"],{% endif %}
                                    {% if intf.from_vlan.tag is defined and intf.from_vlan.tag != none -%}
                                    "tag": "{{ intf.from_vlan.tag }}",{% endif %}
                                    "name": "{{ intf.from_vlan.name }}",
                                    "networkBlockId": {% if intf.from_vlan.block_id is defined -%}
                                    "{{ intf.from_vlan.block_id }}"{% else %}""{% endif %}
                                },
                                "toBigipVlan":{
                                    "path": "{{ intf.to_vlan.path }}",
                                    "create": {{ intf.to_vlan.create | tojson }},
                                    {% if intf.to_vlan.interface is defined -%}
                                    "interface": ["{{ intf.to_vlan.interface }}"],{% endif %}
                                    {% if intf.to_vlan.tag is defined and intf.to_vlan.tag != none -%}
                                    "tag": "{{ intf.to_vlan.tag }}",{% endif %}
                                    "name": "{{ intf.to_vlan.name }}",
                                    "networkBlockId": {% if intf.to_vlan.block_id is defined -%}
                                    "{{ intf.to_vlan.block_id }}"{% else %}""{% endif %}
                                }
                            }
                        {% if not loop.last %},{% endif %}{% endfor %}]
                        {% else %}[]{% endif %}
                     },
                     "loadBalancing":{
                        "devices": {% if params.devices_ips is defined %}[{% for device in params.devices_ips %}{
                           "ratio": {% if device.ratio is defined and device.ratio != none -%}
                           "{{ device.ratio }}"{% else %}"1"{% endif %},
                           "port": "0",
                           "ip": {{ device.ip | tojson }}
                        }{% if not loop.last %},{% endif %}{% endfor %}]{% else %}[]{% endif %},
                         "monitor":{
                             "fromSystem": "{{ params.monitor }}"
                         }
                     },
                     "portRemap": {% if params.port_remap %}true{% else %}false{% endif %},
                     "httpPortRemapValue": {% if params.port_remap -%}{{ params.port_remap }},{% else %}80,
                      {% endif %}
                     "serviceDownAction": "{{ params.service_down_action }}",
                     "iRuleReference":"",{% if params.sslo_version >= 14 %}
                     "mode": "{{ params.mode }}",{% endif %}
                     "iRuleList":{% if params.rules is defined %}{{ params.rules | tojson }}{% else %}[]{% endif %},{% if params.sslo_version >= 13 %}
                     "iRuleListEgress":{% if params.rules_egress is defined %}{{ params.rules_egress | tojson }}{% else %}[]{% endif %},{% endif %}
                     {% if params.sslo_version >= 14 %}
                     "defaultPersistenceProfile": "{% if params.default_persistence_profile %}{{ params.default_persistence_profile }}{% endif %}",{% endif %}
                     "managedNetwork":{
                         "serviceType": "L2",
                         "ipFamily": "both",
                         "ipv4":{
                             "serviceType": "L2",
                             "ipFamily": "ipv4",
                             "serviceSubnet": "{{ params.service_subnet.ipv4 }}",
                             "serviceIndex": {{ params.service_index | default(0) }},
                             "subnetMask": "255.255.255.0"
                         },
                         "ipv6":{
                             "serviceType": "L2",
                             "ipFamily": "ipv6",
                             "serviceSubnet": "{{ params.service_subnet.ipv6 }}",
                             "serviceIndex": {{ params.service_index | default(0) }},
                             "subnetMask": "ffff:ffff:ffff:ffff::"
                         },
                         "operation":"RESERVEANDCOMMIT"
                     }
                 },
                 "vendorInfo":{
                     "name": "{{ params.vendor_info }}"
                 },
                 "modifiedNetworkObjects": {% if params.networks is defined %}[{% for network in params.networks %}
                    {
                        "partition": "Common",
                        "strictness": false,
                        "name": "{{ network.name }}",
                        "previousVersion": {{ params.sslo_version }},
                        "version": {{ params.sslo_version }},
                        "vlan":{
                            "create": true,
                            "path": "{{ network.path }}",
                            "interface":[
                                "{{ network.interface }}"
                            ],
                            "name": "{{ network.name }}"{% if network.tag is defined and network.tag != none %},
                            "tag": "{{ network.tag }}"{%- endif %}

                        },
                        "selfIpConfig":{
                            "selfIp": "",
                            "netmask": "",
                            "floating": false,
                            "HAstaticIpMap":[
                                {
                                "deviceMgmtIp": "",
                                "selfIp": ""
                                }
                            ]
                        },
                        "routeDomain":{
                            "create": false,
                            "id": 0,
                            "path": ""
                        }
                    }{% if not loop.last %},{% endif %}{% endfor %}]{% else %}[]{% endif %},
                 "removedNetworks": [],
                 "networkObjects": [],
                 "fromToVlan": {% if params.interfaces is defined %}[{% for intf in params.interfaces %}
                    {
                        "fromBigipVlan": {
                            "create": {{ intf.from_vlan.create | tojson }},
                            "path": "{{ intf.from_vlan.path }}",
                            {% if intf.from_vlan.interface is defined -%}"interface": ["{{ intf.from_vlan.interface }}"],{% endif %}
                            {% if intf.from_vlan.tag is defined and intf.from_vlan.tag != none -%}"tag": "{{ intf.from_vlan.tag }}",{% endif %}
                            "name": "{{ intf.from_vlan.name }}"
                        },
                        "toBigipVlan": {
                            "create": {{ intf.to_vlan.create | tojson }},
                            "path": "{{ intf.to_vlan.path }}",
                            {% if intf.to_vlan.interface is defined -%}"interface": ["{{ intf.to_vlan.interface }}"],{% endif %}
                            {% if intf.to_vlan.tag is defined and intf.to_vlan.tag != none -%}"tag": "{{ intf.to_vlan.tag }}",{% endif %}
                            "name": "{{ intf.to_vlan.name }}"
                        }
                    }{% if not loop.last %},{% endif %}{% endfor %}]{% else %}[]{% endif %},
                 "fromVlan": {% if params.interfaces is defined and params.interfaces|length > 0 %}{
                    "fromBigipVlan": {
                        "create": {{ params.interfaces[0].from_vlan.create | tojson }},
                        "path": "{{ params.interfaces[0].from_vlan.path }}",
                        {% if params.interfaces[0].from_vlan.interface is defined -%}
                        "interface": ["{{ params.interfaces[0].from_vlan.interface }}"],{% endif %}
                        {% if params.interfaces[0].from_vlan.tag is defined
                            and params.interfaces[0].from_vlan.tag != none -%}
                        "tag": "{{ params.interfaces[0].from_vlan.tag }}",{% endif %}
                        "name": "{{ params.interfaces[0].from_vlan.name }}"
                    },
                    "toBigipVlan": {
                        "create": {{ params.interfaces[0].to_vlan.create | tojson }},
                        "path": "{{ params.interfaces[0].to_vlan.path }}",
                        {% if params.interfaces[0].to_vlan.interface is defined -%}
                        "interface": ["{{ params.interfaces[0].to_vlan.interface }}"],{% endif %}
                        {% if params.interfaces[0].to_vlan.tag is defined
                            and params.interfaces[0].to_vlan.tag != none -%}
                        "tag": "{{ params.interfaces[0].to_vlan.tag }}",{% endif %}
                        "name": "{{ params.interfaces[0].to_vlan.name }}"
                    }
                 }{% else %}{}{% endif %},
                 "name": "{{ params.deployment_name }}",
                 "description": "Type: L2",
                 "useTemplate": false,
                 "serviceTemplate": "",
                 "partition": "Common",
                 "advancedMode": "off",
                 "iRulesSelected": {% if params.rules is defined %}{{ params.rules | tojson }}
                 {% else %}[]{% endif %}{% if params.sslo_version >= 13 %},
                 "iRulesSelectedEgress": {% if params.rules_egress is defined %}{{ params.rules_egress | tojson }}
                 {% else %}[]{% endif %}{% endif %}{% if params.block_id is defined %},
                 "existingBlockId": "{{ params.block_id }}"{% endif %}
             }
         },
         {
             "id": "f5-ssl-orchestrator-service-chain",
             "type": "JSON",
             "value": []
         },
         {
             "id": "f5-ssl-orchestrator-policy",
             "type": "JSON",
             "value": []
         }
     ],
     "dataProperties":[],
     "configurationProcessorReference": {
         "link": "https://localhost/mgmt/shared/iapp/processors/f5-iappslx-ssl-orchestrator-gc"
     },
     "configProcessorTimeoutSeconds": 120,
     "statsProcessorTimeoutSeconds": 60,
     "configProcessorAffinity": {
         "processorPolicy": "LOCAL",
         "affinityProcessorReference": {
            "link": "https://localhost/mgmt/shared/iapp/affinity/local"
         }
     },
     "state": "BINDING",
     "presentationHtmlReference": {
         "link": "https://localhost/iapps/f5-iappslx-ssl-orchestrator/sgc/sgcIndex.html"
     }
}
"""
