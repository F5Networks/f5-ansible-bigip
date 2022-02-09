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
                "deploymentType": "AUTHENTICATION",
                "operationType": "{{ params.operation }}",
                "version": {{ params.sslo_version }},
                "partition": "Common"
            }
        },
        {
            "id": "f5-ssl-orchestrator-authentication",
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
                "deploymentType": "AUTHENTICATION"{% if params.dep_ref is defined %},
                "deploymentReference": "{{ params.dep_ref }}" {% endif %}
            }
        },
        {
            "id":"f5-ssl-orchestrator-authentication",
            "type":"JSON",
            "value":{
               "name": "{{ params.deployment_name }}",
               "description":"OCSP Responder",
               "authType":"ocsp",
               "serverDef":{
                  "source": "{{ params.ocsp_source }}",
                  "destination":{
                     "address": "{{ params.ocsp_dest }}",
                     "port": {{ params.ocsp_port }},
                     "mask":""
                  },
                  "vlans": {{ params.ocsp_vlans | tojson }},
                  "serverTcpProfile": "{{ params.ocsp_tcp_settings_client }}",
                  "clientTcpProfile": "{{ params.ocsp_tcp_settings_server }}",
                  "httpProfile": "{{ params.ocsp_http_profile }}",
                  "sslSettingReference": "{{ params.ocsp_ssl_profile }}"
               },
               "vendorInfo":{
                  "name":"OCSP Responder",
                  "product":"",
                  "model":"",
                  "version":""
               },
               "ocsp":{
                  "useExisting": {{ params.use_existing | tojson }},
                  "ocspProfile": {% if params.existing_ocsp is defined and params.existing_ocsp != ""%}{{ params.existing_ocsp }},{% else %}"",{% endif %}
                  "maxAge": {{ params.ocsp_max_age }},
                  "nonce": "{{ params.ocsp_nonce }}",
                  "fqdn": "{{ params.ocsp_fqdn }}"
               },
               "useTemplate": false,
               "authTemplate":"",
               "partition":"Common",
               "previousVersion": {{ params.sslo_version }},
               "version": {{ params.sslo_version }},
               "strictness": false{% if params.block_id is defined %},
               "existingBlockId": "{{ params.block_id }}"{% endif %}
            }
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
