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
                "deploymentType": "TOPOLOGY"{% if params.dep_ref is defined %},
                "deploymentReference": "{{ params.dep_ref }}"{% endif %}
           }
       },
       {
           "id": "f5-ssl-orchestrator-topology",
           "type": "JSON",
           "value": {
               "name": "{{ params.deployment_name }}",
               "type": "{{ params.topology }}",
               "version": {{ params.sslo_version }},
               "previousVersion": {{ params.sslo_version }},
               "partition": "Common",
               "strictness": false,
               "userCreated": false,
               "description": "",
               "deployedNetwork": {% if params.dep_net is defined %}"{{ params.dep_net }}"{% else %}""{% endif %},
               "ipFamily": "{{ params.ip_family }}",
               "ruleType": "{{ params.rule }}",
               "ruleLabel": "{{ params.rule }}",
               "dnsResolver": {% if params.dns_desolver is defined %}"{{ params.dns_desolver }}"{% else %}""{% endif %},
               "serviceDef": {
                   "description": "",
                   "source": {% if params.source is defined %}"{{ params.source }}"{% else %}"0.0.0.0%0/0"{% endif %},
                   "protocol": {% if params.protocol is defined %}"{{ params.protocol }}"{% else %}"tcp"{% endif %},
                   "destination": {
                       "mask": "",
                       "port": {% if params.port is defined %}{{ params.port }}{% else %}0{% endif %},
                       "prefix": 0,
                       "address": {% if params.dest is defined %}"{{ params.dest }}"{% else %}"0.0.0.0%0/0"{% endif %}
                   }
               },
               "pool": {% if params.pool is defined %}"{{ params.pool }}"{% else %}""{% endif %},
               "tlsEnabled": true,
               "iRules": [
                  {
                    "name": "",
                    "value": ""
                  }
               ],
               "l7Protocols": {% if params.additional_protocols is defined -%}
                {{ params.additional_protocols | tojson }}{% else %}[]{% endif %},
               "l7Profile": {% if params.l7_profile is defined %}"{{ params.l7_profile }}"{% else %}""{% endif %},
               "l7ProfileType": {% if params.l7_profile_type is defined -%}
                "{{ params.l7_profile_type }}"{% else %}""{% endif %},
               "tcpSettings": {
                   "clientTcpProfile": {% if params.tcp_settings_client is defined -%}
                    "{{ params.tcp_settings_client }}"{% else %}""{% endif %},
                   "serverTcpProfile": {% if params.tcp_settings_server is defined -%}
                    "{{ params.tcp_settings_server }}"{% else %}""{% endif %}
               },
               "udpSettings": {
                   "clientUdpProfile": "",
                   "serverUdpProfile": ""
               },
               "fastL4Settings": {
                   "all": ""
               },
               "ingressNetwork": {
                  "vlans": {% if params.vlans is defined %}{{ params.vlans | tojson }}{% else %}[]{% endif %}
               },
               "egressNetwork": {
                  "clientSnat": "{{ params.snat }}",
                  "snat": {
                      "referredObj": {% if params.snat_ref_id is defined %}"{{ params.snat_ref_id }}"
                      {% else %}""{% endif %},
                      "ipv4SnatAddresses": {% if params.ip_family == 'ipv4' and params.snat_list is defined %}
                      {{ params.snat_list | tojson }}{% else %}[]{% endif %},
                      "ipv6SnatAddresses": {% if params.ip_family == 'ipv6' and params.snat_list is defined %}
                      {{ params.snat_list | tojson }}{% else %}[]{% endif %}
                   },
                   "gatewayOptions": "{{ params.gateway }}",
                   "outboundGateways": {
                      "referredObj": {% if params.gw_ref_id is defined %}"{{ params.gw_ref_id }}"
                      {% else %}""{% endif %},
                      "ipv4SnatAddresses": {% if params.ip_family == 'ipv4' and params.gateway_list is defined -%}
                      {{ params.gateway_list | tojson }}{% else %}[]{% endif %},
                      "ipv6SnatAddresses": {% if params.ip_family == 'ipv6' and params.gateway_list is defined -%}
                      {{ params.gateway_list | tojson }}{% else %}[]{% endif %}
                   }
               },{% if params.ocsp_auth is defined %}
               "ocspAuth": "{{ params.ocsp_auth }}",{% endif %}
               "proxySettings": {
                  "proxyType": {% if params.proxy_type is defined -%}"{{ params.proxy_type }}"
                      {% else %}""{% endif %},{% if params.verify_accept is defined %}
                  "tcpProfile": {
                      "verifyAccept": {{ params.verify_accept | tojson }}
                  },{% endif %}
                  "forwardProxy": {
                      "explicitProxy": {
                          "ipv4Port": {% if params.ip_family == 'ipv4' and params.proxy_port is defined -%}
                          {{ params.proxy_port }}{% else %}3128{% endif %},
                          "ipv6Port": {% if params.ip_family == 'ipv6' and params.proxy_port is defined -%}
                          {{ params.proxy_port }}{% else %}3128{% endif %},
                          "ipv4Address": {% if params.ip_family == 'ipv4' and params.proxy_ip is defined -%}
                          "{{ params.proxy_ip }}"{% else %}""{% endif %},
                          "ipv6Address": {% if params.ip_family == 'ipv6' and params.proxy_ip is defined -%}
                          "{{ params.proxy_ip }}"{% else %}""{% endif %}
                      },
                      "transparentProxy": {
                          "passNonTcpNonUdpTraffic": false,
                          "tcpTrafficPassThroughType": true
                      }
                  },
                  "reverseProxy": {
                     "ipv4Address": "",
                     "ipv4Port": 0,
                     "ipv6Address": "",
                     "ipv6Port": 0
                  }
               },
               "advancedMode": "off",
               "iRulesList": [],
                "loggingConfig": {
                    "logPublisher": "none",
                    "statsToRecord": 0,
                    "perRequestPolicy": {% if params.logging is defined and 'per_request_policy' in params.logging -%}
                    "{{ params.logging.per_request_policy }}"{% else %}"err"{% endif %},
                    "ftp": {% if params.logging is defined and 'ftp' in params.logging -%}
                    "{{ params.logging.ftp }}"{% else %}"err"{% endif %},
                    "imap": {% if params.logging is defined and 'imap' in params.logging -%}
                    "{{ params.logging.imap }}"{% else %}"err"{% endif %},
                    "pop3": {% if params.logging is defined and 'pop3' in params.logging -%}
                    "{{ params.logging.pop3 }}"{% else %}"err"{% endif %},
                    "smtps": {% if params.logging is defined and 'smpts' in params.logging -%}
                    "{{ params.logging.smpts }}"{% else %}"err"{% endif %},
                    "sslOrchestrator": {% if params.logging is defined and 'sslo' in params.logging -%}
                    "{{ params.logging.sslo }}"{% else %}"err"{% endif %}
               },
               "authProfile": {% if params.auth_profile is defined -%}
                "{{ params.auth_profile }}"{% else %}""{% endif %},
               "sslSettingReference": {% if params.ssl_settings is defined -%}
                "{{ params.ssl_settings }}"{% else %}""{% endif %},
               "securityPolicyReference": {% if params.security_policy is defined -%}
                "{{ params.security_policy }}"{% else %}""{% endif %},
               "accessProfile": "{{ params.access_profile }}"{% if params.profile_scope is defined -%},
               "accessProfileScope": "{{ params.profile_scope }}"{% endif %}
                {%- if params.profile_scope_value is defined -%},
               "accessProfileNameScopeValue": "{{ params.profile_scope_value }}"{% endif %}
                {%- if params.primary_auth_uri is defined -%},
               "primaryAuthenticationURI": "{{ params.primary_auth_uri }}"{% endif %}
                {%- if params.block_id is defined -%},
               "existingBlockId": "{{ params.block_id }}"{% endif %}
           }
       },
       {
           "id": "f5-ssl-orchestrator-general-settings",
           "type": "JSON",
           "value": {% if params.resolver is defined %}{{ params.resolver | tojson }}{% else %}{}{% endif %}
       },
       {
           "id": "f5-ssl-orchestrator-tls",
           "type": "JSON",
           "value": {% if params.ssldef is defined %}{{ params.ssldef | tojson }}{% else %}{}{% endif %}
       },
       {
           "id": "f5-ssl-orchestrator-service-chain",
           "type": "JSON",
           "value": {% if params.service_chain is defined %}{{ params.service_chain | tojson }}{% else %}[]{% endif %}
       },
       {
           "id": "f5-ssl-orchestrator-service",
           "type": "JSON",
           "value": {% if params.services is defined %}{{ params.services | tojson }}{% else %}[]{% endif %}
       },
       {
           "id": "f5-ssl-orchestrator-network",
           "type": "JSON",
           "value": {% if params.network is defined %}{{ params.network | tojson }}{% else %}[]{% endif %}
       },
       {
           "id": "f5-ssl-orchestrator-intercept-rule",
           "type": "JSON",
           "value": {% if params.intercept_rule is defined -%}{{ params.intercept_rule | tojson }}
            {% else %}[]{% endif %}
       },
       {
           "id": "f5-ssl-orchestrator-policy",
           "type": "JSON",
           "value": {% if params.policy is defined -%}{{ params.policy | tojson }}{% else %}{}{% endif %}
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
                "deploymentType": "TOPOLOGY",
                "operationType": "{{ params.operation }}",
                "version": {{ params.sslo_version }},
                "partition": "Common"
            }
        },
        {
            "id": "f5-ssl-orchestrator-topology",
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
