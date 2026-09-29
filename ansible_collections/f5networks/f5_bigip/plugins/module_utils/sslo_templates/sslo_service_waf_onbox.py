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
    "inputProperties": [
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
            "id": "f5-ssl-orchestrator-service",
            "type": "JSON",
            "value": [{
                "name": "{{ params.deployment_name }}",
                "vendorInfo": {
                    "name": "F5 Advanced WAF (On-Box)"
                },
                "customService": {
                    "name": "{{ params.deployment_name }}",
                    "serviceDownAction": "reset",
                    "serviceType": "awaf",
                    "serviceSpecific": {
                        "name": "{{ params.deployment_name }}",
                        "appSecurityPolicy": "{{ params.waf_policy }}",
                        "dosProtectionProfile": {% if params.dos_protection_profile is defined %}"{{ params.dos_protection_profile }}"{% else %}""{% endif %},
                        "botDefenseProfile": {% if params.bot_defense_profile is defined %}"{{ params.bot_defense_profile }}"{% else %}""{% endif %},
                        "appCloudSecurityService": [],
                        "logProfile": {{ params.log_profiles | tojson }},
                        "iRuleList": {{ params.rules | tojson }}
                    }
                },
                "description": "Type: awaf",
                "strictness": true,
                "useTemplate": false,
                "serviceTemplate": "",
                "partition": "Common",
                "previousVersion": {{ params.sslo_version }},
                "version": {{ params.sslo_version }}{% if params.block_id is defined %},
                "existingBlockId": "{{ params.block_id }}"{% endif %}
            }]
        },
        {
            "id": "f5-ssl-orchestrator-network",
            "type": "JSON",
            "value": []
        }
    ],
    "configurationProcessorReference": {
        "link": "https://localhost/mgmt/shared/iapp/processors/f5-iappslx-ssl-orchestrator-gc"
    },
    "state": "BINDING",
    "presentationHtmlReference": {
        "link": "https://localhost/iapps/f5-iappslx-ssl-orchestrator/sgc/sgcIndex.html"
    },
    "operation": "{{ params.operation }}"
}
"""
