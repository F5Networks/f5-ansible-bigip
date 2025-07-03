create_modify = """
{
   "policy" : {
      "name": "{{ params.name }}",
      "fullPath": "{{ params.fullPath }}",
      "applicationLanguage": "{{ params.language }}",
      "caseInsensitive": {{ params.case_insensitive | tojson }},{% if params.description is defined %}
      "description": "{{ params.description }}",{% endif %}
      "enablePassiveMode": {{ params.enable_passive_mode | tojson }},
      "protocolIndependent" : {{ params.protocol_independent | tojson }},
      "enforcementMode": "{{ params.enforcement_mode }}",
      "template": {{ params.template | tojson }},
      "server-technologies": {{ params.server_technologies | tojson }},{% if params.open_api_files is defined %}
      "open-api-files": {{ params.open_api_files | tojson }},{% endif %}{% if params.file_types is defined %}
      "filetypes": {{ params.file_types | tojson }},{% endif %}{% if params.ip_intel is defined %}
      "ip-intelligence": {{ params.ip_intel | tojson }},{% endif %}{% if params.parameters is defined %}
      "parameters": {{ params.parameters | tojson }},{% endif %}{% if params.policy_builder is defined %}
      "policy-builder": {{ params.policy_builder | tojson }},{% endif %}{% if params.pb_server_tech is defined %}
      "policy-builder-server-technologies" : {{ params.pb_server_tech | tojson }},{% endif %}{% if params.pb_central_config is defined %}
      "policy-builder-central-configuration": {{ params.pb_central_config | tojson }},{% endif %}{% if params.pb_cookie is defined %}
      "policy-builder-cookie": {{ params.pb_cookie | tojson }},{% endif %}{% if params.pb_filetype is defined %}
      "policy-builder-filetype": {{ params.pb_filetype | tojson }},{% endif %}{% if params.pb_header is defined %}
      "policy-builder-header": {{ params.pb_header | tojson }},{% endif %}{% if params.pb_param is defined %}
      "policy-builder-parameter": {{ params.pb_param | tojson }},{% endif %}{% if params.pb_redirect_prot is defined %}
      "policy-builder-redirection-protection": {{ params.pb_redirect_prot | tojson }},{% endif %}{% if params.pb_sess_and_logins is defined %}
      "policy-builder-sessions-and-logins": {{ params.pb_sess_and_logins | tojson }},{% endif %}{% if params.pb_url is defined %}
      "policy-builder-url": {{ params.pb_url | tojson }},{% endif %}{% if params.behavioral_enforce is defined %}
      "behavioral-enforcement": {{ params.behavioral_enforce | tojson }},{% endif %}{% if params.urls is defined %}
      "urls": {{ params.urls | tojson }},{% endif %}{% if params.signature_sets is defined %}
      "signature-sets": {{ params.signature_sets | tojson }},{% endif %}{% if params.signature_settings is defined %}
      "signature-settings": {{ params.signature_settings | tojson }},{% endif %}{% if params.cookies is defined %}
      "cookies": {{ params.cookies | tojson }},{% endif %}{% if params.general is defined %}
      "general": {{ params.general | tojson }},{% endif %}{% if params.headers is defined %}
      "headers": {{ params.headers | tojson }},{% endif %}{% if params.methods is defined %}
      "methods": {{ params.methods | tojson }},{% endif %}{% if params.blocking_settings is defined %}
      "blocking-settings": {{ params.blocking_settings | tojson }},{% endif %}{% if params.brute_force_atck_prev is defined %}
      "brute-force-attack-preventions": {{ params.brute_force_atck_prev | tojson }},{% endif %}{% if params.character_sets is defined %}
      "character-sets": {{ params.character_sets | tojson }},{% endif %}{% if params.cookie_settings is defined %}
      "cookie-settings": {{ params.cookie_settings | tojson }},{% endif %}{% if params.csrf_protection is defined %}
      "csrf-protection": {{ params.csrf_protection | tojson }},{% endif %}{% if params.csrf_urls is defined %}
      "csrf-urls": {{ params.csrf_urls | tojson }},{% endif %}{% if params.data_guard is defined %}
      "data-guard": {{ params.data_guard | tojson }},{% endif %}{% if params.database_protection is defined %}
      "database-protection": {{ params.database_protection | tojson }},{% endif %}{% if params.deception_settings is defined %}
      "deception-settings": {{ params.deception_settings | tojson }},{% endif %}{% if params.graphql_profiles is defined %}
      "graphql-profiles": {{ params.graphql_profiles | tojson }},{% endif %}{% if params.gwt_profiles is defined %}
      "gwt-profiles": {{ params.gwt_profiles | tojson }},{% endif %}{% if params.header_settings is defined %}
      "header-settings": {{ params.header_settings | tojson }},{% endif %}{% if params.json_profiles is defined %}
      "json-profiles": {{ params.json_profiles | tojson }},{% endif %}{% if params.login_enforcement is defined %}
      "login-enforcement": {{ params.login_enforcement | tojson }},{% endif %}{% if params.plain_text_profiles is defined %}
      "plain-text-profiles": {{ params.plain_text_profiles | tojson }},{% endif %}{% if params.redir_prot_dom is defined %}
      "redirection-protection-domains": {{ params.redir_prot_dom | tojson }},{% endif %}{% if params.resp_pages is defined %}
      "response-pages": {{ params.resp_pages | tojson }},{% endif %}{% if params.sens_params is defined %}
      "sensitive-parameters": {{ params.sens_params | tojson }},{% endif %}{% if params.sess_tracking is defined %}
      "session-tracking": {{ params.sess_tracking | tojson }},{% endif %}{% if params.threat_camp_sett is defined %}
      "threat-campaign-settings": {{ params.threat_camp_sett | tojson }},{% endif %}{% if params.websock_urls is defined %}
      "websocket-urls": {{ params.websock_urls | tojson }},{% endif %}{% if params.xml_profiles is defined %}
      "xml-profiles": {{ params.xml_profiles | tojson }},{% endif %}
      "type": "{{ params.type }}"
   },
   {% if params.modifications is defined %}
      "modifications" : {{ params.modifications | tojson }}
   {% endif %}
}
"""
