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
                "deploymentType": "SECURITY_POLICY",
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
            "id": "f5-ssl-orchestrator-policy",
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
                "deploymentType": "SECURITY_POLICY"{% if params.dep_ref is defined %},
                "deploymentReference": "{{ params.dep_ref }}"{% endif %}
          }
       },
       {
          "id":"f5-ssl-orchestrator-policy",
          "type":"JSON",
          "value":{
                "existingReference": "",
                "policyName": "",
                "description": "",
                "isTemplate": "",
                "rules": {{ params.policy_rules | tojson }},
                "defaultAction": "",
                "defaultActionOptions": {},
                "serverCertStatusCheck": {{ params.servercert_check | tojson }},
                "templateOptions": {},
                "policyConsumer": {
                    "type": "{{ params.policy_consumer }}",
                    "subType": "{{ params.policy_consumer }}"
                },
                "isDefaultPinnersSet": true,
                "proxyConfigurations": {{ params.proxy_connect | tojson }},
                "type": "custom",
                "strictness": false,
                "partition": "Common",
                "serviceChains": {},
                "pools": {{ params.pools | tojson }},
                "name": "{{ params.deployment_name }}",
                "language": "en",
                "previousVersion": {{ params.sslo_version }},
                "version": {{ params.sslo_version }}{% if params.block_id is defined %},
                "existingBlockId": "{{ params.block_id }}"{% endif %}
          }
       },
       {
          "id": "f5-ssl-orchestrator-general-settings",
          "type": "JSON",
          "value": {}
       },
       {
          "id":"f5-ssl-orchestrator-service-chain",
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

create_modify2 = """
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
                "deploymentType": "SECURITY_POLICY"{% if params.dep_ref is defined %},
                "deploymentReference": "{{ params.dep_ref }}"{% endif %}
          }
       },
       {
          "id":"f5-ssl-orchestrator-policy",
          "type":"JSON",
          "value":{
                "existingReference": "",
                "policyName": "",
                "description": "",
                "isTemplate": "",
                "rules": {{ params.policy_rules | tojson }},
                "defaultAction": "",
                "defaultActionOptions": {},
                "serverCertStatusCheck": {{ params.servercert_check | tojson }},
                "templateOptions": {},
                "policyConsumer": {
                    "type": "{{ params.policy_consumer }}",
                    "subType": "{{ params.policy_consumer }}"
                },
                "isDefaultPinnersSet": true,
                "proxyConfigurations": {
                    "isProxyChainEnabled": true,
                    "pool": {
                        "create": true,
                        "members": [
                            {
                                "ip": "192.168.20.10",
                                "port": "3128"
                            }
                        ],
                        "name": "/Common/ssloP_testpolicy.app/ssloP_testpolicy_proxyChainPool"
                    },
                    "username": "testuser",
                    "password": "testpassword"
                },
                "type": "custom",
                "strictness": true,
                "partition": "Common",
                "serviceChains": {},
                "pools": {
                    "ssloP_testpolicy_proxyChainPool": {
                        "name": "ssloP_testpolicy_proxyChainPool",
                        "loadBalancingMode": "predictive-node",
                        "monitors": {
                            "names": [
                                "/Common/gateway_icmp"
                            ]
                        },
                        "members": [
                            {
                                "ip": "192.168.20.10",
                                "port": "3128",
                                "appService": "ssloP_testpolicy.app/ssloP_testpolicy",
                                "subPath": "ssloP_testpolicy.app"
                            }
                        ],
                        "unhandledPool": true,
                        "minActiveMembers": "0",
                        "callerContext": "policyConfigProcessor"
                    }
                },
                "name": "{{ params.deployment_name }}",
                "language": "en",
                "previousVersion": {{ params.sslo_version }},
                "version": {{ params.sslo_version }}{% if params.block_id is defined %},
                "existingBlockId": "{{ params.block_id }}"{% endif %}
          }
       },
       {
          "id": "f5-ssl-orchestrator-general-settings",
          "type": "JSON",
          "value": {}
       },
       {
          "id":"f5-ssl-orchestrator-service-chain",
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

create_modify3 = """
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
                "deploymentType": "SECURITY_POLICY"{% if params.dep_ref is defined %},
                "deploymentReference": "{{ params.dep_ref }}"{% endif %}
          }
       },
       {
          "id":"f5-ssl-orchestrator-policy",
          "type":"JSON",
          "value":{
                "existingReference": "",
                "policyName": "",
                "description": "",
                "isTemplate": "",
                "rules": [
                    {
                        "name": "Pinners_Rule",
                        "operation": "AND",
                        "mode": "edit",
                        "conditions": [
                            {
                                "index": 1.646743266322E12,
                                "type": "SSL Check",
                                "options": {
                                    "ssl": true
                                }
                            },
                            {
                                "index": 1.646743266323E12,
                                "type": "SNI Category Lookup",
                                "options": {
                                    "category": [
                                        "Pinners"
                                    ]
                                }
                            }
                        ],
                        "action": "allow",
                        "actionOptions": {
                            "ssl": "bypass",
                            "serviceChain": ""
                        },
                        "index": 1.646939347692E12,
                        "phase": 2.0
                    },
                    {
                        "name": "testrule",
                        "operation": "OR",
                        "conditions": [
                            {
                                "index": 1.646818710993E12,
                                "type": "SNI Category Lookup",
                                "options": {
                                    "category": [
                                        "General Email"
                                    ]
                                }
                            },
                            {
                                "index": 1.646846304464E12,
                                "type": "Client Port Match",
                                "options": {
                                    "port": [
                                        "80",
                                        "443"
                                    ]
                                }
                            },
                            {
                                "index": 1.646852660955E12,
                                "type": "Category Lookup",
                                "options": {
                                    "category": [
                                        "Financial Data and Services",
                                        "Health and Medicine"
                                    ]
                                }
                            },
                            {
                                "index": 1.646939380328E12,
                                "type": "Client IP Geolocation",
                                "options": {
                                    "geolocations": [
                                        {
                                            "matchType": "countryCode",
                                            "value": "IN"
                                        },
                                        {
                                            "matchType": "countryName",
                                            "value": "USA"
                                        },
                                        {
                                            "matchType": "continent",
                                            "value": "ASIA"
                                        },
                                        {
                                            "matchType": "state",
                                            "value": "Texas"
                                        }
                                    ]
                                }
                            }
                        ],
                        "action": "reject",
                        "actionOptions": {
                            "ssl": "",
                            "serviceChain": ""
                        },
                        "index": 1.646939347693E12,
                        "mode": "edit",
                        "valid": true,
                        "phase": 2.0,
                        "injectCategorizationMacro": true
                    },
                    {
                        "name": "All Traffic",
                        "action": "allow",
                        "mode": "edit",
                        "actionOptions": {
                            "ssl": "intercept",
                            "serviceChain": ""
                        },
                        "isDefault": true,
                        "index": 1.646939347694E12,
                        "phase": 2.0
                    }
                ],
                "defaultAction": "",
                "defaultActionOptions": {},
                "serverCertStatusCheck": false,
                "templateOptions": {},
                "policyConsumer": {
                    "type": "Outbound",
                    "subType": "Outbound"
                },
                "isDefaultPinnersSet": true,
                "proxyConfigurations": {
                    "isProxyChainEnabled": true,
                    "pool": {
                        "create": true,
                        "members": [
                            {
                                "ip": "192.168.20.10",
                                "port": "3128"
                            }
                        ],
                        "name": "/Common/ssloP_testpolicy.app/ssloP_testpolicy_proxyChainPool"
                    },
                    "username": "testuser",
                    "password": "116101115116112097115115119111114100"
                },
                "type": "custom",
                "strictness": true,
                "partition": "Common",
                "serviceChains": {},
                "pools": {
                    "ssloP_testpolicy_proxyChainPool": {
                        "name": "ssloP_testpolicy_proxyChainPool",
                        "loadBalancingMode": "predictive-node",
                        "monitors": {
                            "names": [
                                "/Common/gateway_icmp"
                            ]
                        },
                        "members": [
                            {
                                "ip": "192.168.20.10",
                                "port": "3128",
                                "appService": "ssloP_testpolicy.app/ssloP_testpolicy",
                                "subPath": "ssloP_testpolicy.app"
                            }
                        ],
                        "unhandledPool": true,
                        "minActiveMembers": "0",
                        "callerContext": "policyConfigProcessor"
                    }
                },
                "name": "{{ params.deployment_name }}",
                "language": "en",
                "previousVersion": {{ params.sslo_version }},
                "version": {{ params.sslo_version }}{% if params.block_id is defined %},
                "existingBlockId": "{{ params.block_id }}"{% endif %}
          }
       },
       {
          "id": "f5-ssl-orchestrator-general-settings",
          "type": "JSON",
          "value": {}
       },
       {
          "id":"f5-ssl-orchestrator-service-chain",
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
