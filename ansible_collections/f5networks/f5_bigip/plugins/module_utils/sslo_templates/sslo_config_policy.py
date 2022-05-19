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
                "serverCertStatusCheck": {{ params.server_cert_check | tojson }},
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
