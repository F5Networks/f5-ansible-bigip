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
                "deploymentType": "SSL_SETTINGS",
                "operationType": "{{ params.operation }}",
                "version": {{ params.sslo_version }},
                "partition": "Common"
            }
        },
        {
            "id": "f5-ssl-orchestrator-tls",
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
                "deploymentType": "SSL_SETTINGS"{% if params.dep_ref is defined %},
                "deploymentReference": "{{ params.dep_ref }}" {% endif %}
            }
       },
       {
          "id":"f5-ssl-orchestrator-tls",
          "type":"JSON",
          "value":{
             "sslSettingsReference":"",
             "sslSettingsName":"",
             "description":"",
             "generalSettings":{
                "isForwardProxy": {% if params.proxy_type == "forward" %}true{% else %}false{% endif %},
                "bypassHandshakeAlert": {{ params.bypass_handshake_failure | tojson }},
                "bypassClientCertFailure": {{ params.bypass_client_cert_failure | tojson }}
             },
             "clientSettings":{
                "ciphers":{
                   "isCipherString": {% if params.client_cipher_type == "string" %}true{% else %}false{% endif %},
                   "cipherString": "{{ params.client_cipher_string }}",
                   "cipherGroup": "{{ params.client_cipher_group }}"
                },
                "certKeyChain":[
                   {
                      "cert": "{{ params.client_cert }}",
                      "key": "{{ params.client_key }}",
                      "chain": {% if params.client_chain is defined %}
                      "{{ params.client_chain }}"{% else %}""{% endif %},
                      "passphrase":"",
                      "name":"CERT_KEY_CHAIN_0"
                   }
                ],
                "caCertKeyChain": {% if params.proxy_type == "forward" %}[
                    {
                        "cert": "{{ params.client_ca_cert }}",
                        "key": "{{ params.client_ca_key }}",
                        "chain": {% if params.client_ca_chain is defined %}
                        "{{ params.client_ca_chain }}"{% else %}""{% endif %},
                        "isCa": true,
                        "usage": "CA",
                        "port": "0",
                        "passphrase": "",
                        "certKeyChainMismatch": false,
                        "isDuplicateVal": false,
                        "name": "CA_CERT_KEY_CHAIN_0"
                    }
                ]{% else %}[]{% endif %},
                "forwardByPass": {% if params.proxy_type == "forward" %}true{% else %}false{% endif %},
                "enabledSSLProcessingOptions": {% if params.client_enable_tls13 is defined %}
                {{ params.client_enable_tls13 | tojson }}
                {% else %}[]{% endif %}{% if params.client_log_publisher is defined %},
                "logPublisher": "{{ params.client_log_publisher }}"{% endif %}{% if params.alpn is defined %},
                "alpn": {{ params.alpn | tojson }}{% endif %}
             },
             "serverSettings":{
                "ciphers":{
                   "isCipherString": {% if params.server_cipher_type == "string" %}true{% else %}false{% endif %},
                   "cipherString": "{{ params.server_cipher_string }}",
                   "cipherGroup": "{{ params.server_cipher_group }}"
                },
                "caBundle": "{{ params.server_ca_bundle }}",
                "expiredCertificates": {{ params.block_expired | tojson }},
                "untrustedCertificates": {{ params.block_untrusted | tojson }},
                "ocsp": "{{ params.ocsp }}",
                "crl": "{{ params.crl }}",
                "enabledSSLProcessingOptions": {% if params.server_enable_tls13 is defined %}
                {{ params.server_enable_tls13 | tojson }}{% else %}[]
                {% endif %}{% if params.server_log_publisher is defined %},
                "logPublisher": "{{ params.server_log_publisher }}"{% endif %}
             },
             "name": "{{ params.deployment_name }}",
             "advancedMode": "off",
             "previousVersion": {{ params.sslo_version }},
             "version": {{ params.sslo_version }},
             "strictness": false{% if params.block_id is defined %},
             "existingBlockId": "{{ params.block_id }}"{% endif %}
          }
       },
       {
          "id":"f5-ssl-orchestrator-topology",
          "type":"JSON"
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
