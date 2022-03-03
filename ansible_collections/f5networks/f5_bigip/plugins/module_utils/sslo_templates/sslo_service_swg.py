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
        "id": "f5-ssl-orchestrator-service",
        "type": "JSON",
        "value": {
            "name": "{{ params.deployment_name }}",
            "vendorInfo":{
               "name":"F5 Secure Web Gateway"
            },
            "customService":{
               "name": "{{ params.deployment_name }}",
               "serviceDownAction": "{{ params.service_down_action }}",
               "serviceType": "swg",
               "serviceSpecific": {
                  "name": "{{ params.deployment_name }}",
                  "description": "",
                  "accessProfile": "{{ params.access_profile }}",
                  "accessProfileScope": "{{ params.profile_scope }}",
                  "logSettings": {{ params.log_settings | tojson }},
                  "accessProfileNameScopeValue": {% if params.named_scope is defined %}"{{ params.named_scope }}"{% else %}""{% endif %},
                  "accessProfileScopeCustSource": "/Common/modern",
                  "perReqPolicy": "{{ params.swg_policy }}",
                  "iRuleList": {{ params.rules | tojson }}
                }
            },
            "description": "Type: swg",
            "useTemplate": false,
            "serviceTemplate": "",
            "partition": "Common",
            "previousVersion": {{ params.sslo_version }},
            "version": {{ params.sslo_version }},
            "strictness": false{% if params.block_id is defined %},
            "existingBlockId": "{{ params.block_id }}"{% endif %}
        }
    },
    {
        "id":"f5-ssl-orchestrator-network",
        "type":"JSON",
        "value":[]
    }
   ],
    "configurationProcessorReference": {
        "link": "https://localhost/mgmt/shared/iapp/processors/f5-iappslx-ssl-orchestrator-gc"
    },
    "state": "BINDING",
    "presentationHtmlReference": {
        "link": "https://localhost/iapps/f5-iappslx-ssl-orchestrator/sgc/sgcIndex.html"
    },
    "operation": "CREATE"
}
"""
