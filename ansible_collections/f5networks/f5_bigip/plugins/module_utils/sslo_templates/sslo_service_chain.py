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
                "deploymentType": "SERVICE_CHAIN",
                "operationType": "{{ params.operation }}",
                "version": {{ params.sslo_version }},
                "partition": "Common"
            }
        },
        {
            "id": "f5-ssl-orchestrator-service-chain",
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
                "deploymentType": "SERVICE_CHAIN"{% if params.dep_ref is defined %},
                "deploymentReference": "{{ params.dep_ref }}" {% endif %}
            }
      },
      {
         "id":"f5-ssl-orchestrator-service-chain",
         "type":"JSON",
         "value": {
               "name": "{{ params.deployment_name }}",
               "description": "",
               "orderedServiceList": {{ params.services | tojson }},
               "partition": "Common",
               "previousVersion": {{ params.sslo_version }},
               "version": {{ params.sslo_version }},
               "strictness": false{% if params.block_id is defined %},
               "existingBlockId": "{{ params.block_id }}"{% endif %}
           }
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
