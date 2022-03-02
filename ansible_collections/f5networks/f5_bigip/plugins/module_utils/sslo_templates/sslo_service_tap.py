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
   "inputProperties": [
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
            "id": "f5-ssl-orchestrator-network",
            "type": "JSON",
            "value": [{%  if params.devices is defined  and 'interface' in params.devices %}
                {
                  "name": "{{ params.devices.name }}",
                  "partition": "Common",
                  "strictness": false,
                  "vlan": {
                    "create": true,
                    "path": "{{ params.devices.path }}",
                    "interface": [
                      "{{ params.devices.interface }}"
                    ]{% if params.devices.tag is defined %},
                    "tag": {{ params.devices.tag }},
                    "networkTag": {{ params.devices.tag }}{% endif %}
                  },
                  "selfIpConfig": {
                    "selfIp": "",
                    "netmask": "",
                    "floating": false,
                    "HAstaticIpMap": [
                      {
                        "deviceMgmtIp": "",
                        "selfIp": ""
                      }
                    ]
                  },
                  "routeDomain": {
                    "create": false,
                    "id": 0,
                    "path": ""
                  }
                }{% endif %}
            ]
      },
      {
            "id": "f5-ssl-orchestrator-service",
            "type": "JSON",
            "value": [
                {
                    "name": "{{ params.deployment_name }}",
                    "vendorInfo": {
                        "name": "Generic TAP Service"
                    },
                    "createNewNetworkObj": {
                        "name": "{{ params.devices.name }}",
                        "networkError": false,
                        "networkInterface": {% if 'interface' in params.devices %}"{{ params.devices.interface }}"{% else %}""{% endif %}
                    },
                    "useExistingNetworkObj": {
                        "path": {% if 'vlan' in params.devices %}"{{ params.devices.path }}"{% else %}""{% endif %},
                        "interface": ""
                    },
                    "customService": {
                        "name": "{{ params.deployment_name }}",
                        "serviceType": "tap",
                        "portRemap": {% if params.port_remap is defined %}true{% else %}false{% endif %},
                        "serviceDownAction": "{{ params.service_down_action }}",
                        "httpPortRemapValue": {{ params.port_remap }},
                        "managedNetwork": {
                            "ipFamily": "both",
                            "serviceType": "tap",
                            "ipv4": {
                                "serviceType": "tap",
                                "ipFamily": "ipv4",
                                "serviceSubnet": "{{ params.devices.ipv4_subnet }}",
                                "serviceIndex": 2,
                                "subnetMask": "255.255.255.252",
                                "serviceSelfIp": "{{ params.devices.ipv4_selfip }}",
                                "serviceHASelfIp": "{{ params.devices.ipv4_haselfip }}",
                                "deviceIp": "{{ params.devices.ipv4_deviceip }}"
                            },
                            "ipv6": {
                                "serviceType": "tap",
                                "ipFamily": "ipv6",
                                "serviceSubnet": "{{ params.devices.ipv6_subnet }}",
                                "serviceIndex": 2,
                                "subnetMask": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0",
                                "serviceSelfIp": "{{ params.devices.ipv6_selfip }}",
                                "serviceHASelfIp": "{{ params.devices.ipv6_haselfip }}",
                                "deviceIp": "{{ params.devices.ipv6_deviceip }}"
                            }
                        },
                        "serviceSpecific": {
                            "description": "",
                            "macAddress": "{{ params.mac_address }}",
                            "name": "{{ params.deployment_name }}",
                            "vlan": {
                                "create": {% if 'vlan' in params.devices %}false{% else %}true{% endif %},
                                "path": "{{ params.devices.path }}",
                                "networkInterface": {% if 'interface' in params.devices %}"{{ params.devices.interface }}"{% else %}""{% endif %},
                                "interface": {% if 'interface' in params.devices %}"{{ params.devices.interface }}"{% else %}""{% endif %},
                                "tag": {% if 'interface' in params.devices and 'tag' in params.devices %}{{ params.devices.tag }}{% else %}0{% endif %},
                                "name": "{{ params.devices.name }}",
                                "networkTag": {% if 'interface' in params.devices and 'tag' in params.devices %}{{ params.devices.tag }}{% else %}0{% endif %}
                            },
                            "vendorConfig": {
                                "name": "TAP Service"
                            }
                        }
                    },
                    "partition": "Common",
                    "templateName": "TAP Service",
                    "useTemplate": false,
                    "previousVersion": {{ params.sslo_version }},
                    "version": {{ params.sslo_version }},
                    "strictness": false{% if params.block_id is defined %},
                    "existingBlockId": "{{ params.block_id }}"{% endif %}
                }
            ]
      },
      {
            "id": "f5-ssl-orchestrator-service-chain",
            "type": "JSON",
            "value": []
      },
      {
         "id":"f5-ssl-orchestrator-policy",
         "type":"JSON",
         "value":[]
      }
   ],
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
    },
    "operation": "CREATE"
}
"""
