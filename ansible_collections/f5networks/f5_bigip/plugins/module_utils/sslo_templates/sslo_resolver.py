create_modify = """{
   "name": "{{ params.name }}",
   "inputProperties":[
      {
         "id":"f5-ssl-orchestrator-operation-context",
         "type":"JSON",
         "value":{
            "version": {{ params.sslo_version }},
            "operationType": "{{ params.operation }}",
            "deploymentType": "GENERAL_SETTINGS",
            "deploymentName": "ssloGS_Global",
            "deploymentReference": {% if params.dep_ref is defined %}"{{ params.dep_ref }}"{% else %}""{% endif %},
            "partition": "Common",
            "strictness": false
         }
      },
      {
         "id":"f5-ssl-orchestrator-general-settings",
         "type":"JSON",
         "value": {
                "name":"ssloGS_global",
                "configModified": true,
                "ipFamily": "{{ params.ip_family }}",
                "dns":{
                    "enableDnsSecurity": {% if params.dns_sec is defined %}}{{ params.dns_sec | tojson }},{% else %}false,{% endif %}
                    "enableLocalDnsQueryResolution": {% if params.fwd_name_servers is defined and params.fwd_name_servers != []%}true{% else %}false{% endif %},
                    "enableLocalDnsZones": {% if params.fwd_zones is defined and params.fwd_zones != []%}true{% else %}false{% endif %},
                    "localDnsZones": {% if params.fwd_zones is defined %}{{ params.fwd_zones | tojson }}{% else %}[]{% endif %},
                    "localDnsNameservers": {% if params.fwd_name_servers is defined %}{{ params.fwd_name_servers | tojson }}{% else %}[]{% endif %}

                },
                "egressNetwork":{
                    "gatewayOptions": "useDefault",
                    "outboundGateways": {
                        "referredObj":"",
                        "ipv4OutboundGateways": [{"ip": "","ratio": 1}],
                        "ipv6NonPublicGateways": [{"ip": ""}],
                        "ipv6OutboundGateways": [{"ip": "","ratio": 1}]
                    }
                },
                "partition":"Common",
                "previousVersion": {{ params.sslo_version }},
                "version": {{ params.sslo_version }},
                "strictness": false,
                "existingBlockId":{% if params.block_id is defined %}"{{ params.block_id }}"{% else %}""{% endif %}{% if params.log_conf is defined %},
                "loggingConfig": {{ params.log_conf | tojson }} {% endif %}
        }
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
