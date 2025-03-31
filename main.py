import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.identity import ClientSecretCredential
from azure.core.exceptions import ClientAuthenticationError
from azure.mgmt.network import NetworkManagementClient 
from azure.mgmt.network.models import (
    FirewallPolicyFilterRuleCollection, 
    ApplicationRule, 
    NetworkRule, 
    NatRule, 
    FirewallPolicyNatRuleCollection
)

def extract_firewall_rules(tenant_id, client_id, client_secret, subscription_id, resource_group, policy_name):
    print("Tenant ID:", tenant_id)
    print("Client ID:", client_id)
    print("Client Secret:", client_secret)
    print("Subscription ID:", subscription_id)

    credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    network_client = NetworkManagementClient(credential, subscription_id)
    
    try:
        rcg_list = network_client.firewall_policy_rule_collection_groups.list(
            resource_group_name=resource_group,
            firewall_policy_name=policy_name
        )

        for rcg in rcg_list:
            print(f"\n{'='*50}\nRule Collection Group: {rcg.name} (Priority: {rcg.priority})")
            
            for rc in rcg.rule_collections or []:
                if isinstance(rc, FirewallPolicyFilterRuleCollection):
                    process_filter_rule_collection(rc)
                elif isinstance(rc, FirewallPolicyNatRuleCollection):
                    process_nat_rule_collection(rc)

    except Exception as e:
        print(f"Error: {str(e)}")

def process_filter_rule_collection(rc):
    print(f"\n  [Filter] Rule Collection: {rc.name} (Priority: {rc.priority})")
    print(f"  Action: {rc.action.type}")
    
    for rule in rc.rules or []:
        if isinstance(rule, ApplicationRule):
            rule_data = extract_application_rule(rule)
            print_rule(rule_data)
        elif isinstance(rule, NetworkRule):
            rule_data = extract_network_rule(rule)
            print_rule(rule_data)

def process_nat_rule_collection(rc):
    print(f"\n  [NAT] Rule Collection: {rc.name} (Priority: {rc.priority})")
    print(f"  Action: {rc.action.type}")
    
    for rule in rc.rules or []:
        if isinstance(rule, NatRule):
            rule_data = extract_nat_rule(rule)
            print_rule(rule_data)
            
def extract_network_rule(rule):
    return {
        'type': 'Network',
        'name': rule.name,
        'description': getattr(rule, 'description', None),
        'sources': {
            'addresses': rule.source_addresses,
            'ip_groups': getattr(rule, 'source_ip_groups', [])
        },
        'destinations': {
            'addresses': rule.destination_addresses,
            'ip_groups': getattr(rule, 'destination_ip_groups', []),
            'fqdns': getattr(rule, 'destination_fqdns', [])
        },
        'ports': rule.destination_ports,
        'protocols': rule.ip_protocols
    }

def extract_nat_rule(rule):
    return {
        'type': 'NAT',
        'name': rule.name,
        'description': getattr(rule, 'description', None),
        'sources': {
            'addresses': rule.source_addresses,
            'ip_groups': getattr(rule, 'source_ip_groups', [])
        },
        'destinations': {
            'addresses': rule.destination_addresses,
            'ports': rule.destination_ports
        },
        'translated': {
            'address': rule.translated_address,
            'port': getattr(rule, 'translated_port', None),
            'fqdn': getattr(rule, 'translated_fqdn', None)
        },
        'protocol': rule.ip_protocols[0] if rule.ip_protocols else None
    }       

def extract_application_rule(rule):
    return {
        'type': 'Application',
        'name': rule.name,
        'description': getattr(rule, 'description', None),
        'sources': {
            'addresses': rule.source_addresses,
            'ip_groups': getattr(rule, 'source_ip_groups', [])
        },
        'protocols': [f"{p.protocol_type}:{p.port}" for p in rule.protocols],
        'destinations': {
            'fqdns': getattr(rule, 'target_fqdns', []),
            'fqdn_tags': getattr(rule, 'fqdn_tags', []),
            'web_categories': getattr(rule, 'web_categories', [])
        }
    }

def print_rule(rule_data):
    print(f"\n    [{rule_data['type']}] Rule: {rule_data['name']}")
    
    if rule_data.get('description'):
        print(f"      Description: {rule_data['description']}")
    
    print("      Sources:")
    if rule_data['sources']['addresses']:
        print(f"        - IP Addresses: {rule_data['sources']['addresses']}")
    if rule_data['sources']['ip_groups']:
        print(f"        - IP Groups: {rule_data['sources']['ip_groups']}")
    
    if rule_data['type'] in ['Application', 'Network']:
        print("      Protocols:" if rule_data['type'] == 'Application' else "      IP Protocols:")
        for proto in (rule_data['protocols'] if isinstance(rule_data['protocols'], list) else [rule_data['protocols']]):
            if proto: print(f"        - {proto}")
    
    print("      Destinations:")
    if rule_data['type'] == 'Application':
        if rule_data['destinations']['fqdns']:
            print(f"        - FQDNs: {rule_data['destinations']['fqdns']}")
        if rule_data['destinations']['fqdn_tags']:
            print(f"        - FQDN Tags: {rule_data['destinations']['fqdn_tags']}")
        if rule_data['destinations']['web_categories']:
            print(f"        - Web Categories: {rule_data['destinations']['web_categories']}")
    else:
        if rule_data.get('destinations', {}).get('addresses'):
            print(f"        - IP Addresses: {rule_data['destinations']['addresses']}")
        if rule_data.get('destinations', {}).get('fqdns'):
            print(f"        - FQDNs: {rule_data['destinations']['fqdns']}")
        if rule_data.get('ports'):
            print(f"        - Ports: {rule_data['ports']}")
    
    if rule_data['type'] == 'NAT':
        print("      Translation:")
        print(f"        - Original Port: {rule_data['destinations']['ports'][0]}")
        print(f"        - Translated to: {rule_data['translated']['address']}:{rule_data['translated']['port']}")
        if rule_data['translated']['fqdn']:
            print(f"        - Translated FQDN: {rule_data['translated']['fqdn']}")

if __name__ == "__main__":
    load_dotenv()

    tenant_id = os.getenv("AZURE_TENANT_ID").strip('"')
    client_id = os.getenv("AZURE_CLIENT_ID").strip('"')
    client_secret = os.getenv("AZURE_CLIENT_SECRET").strip('"')
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID").strip('"')
    resource_group = os.getenv("AZURE_RESOURCE_GROUP").strip('"')
    policy_name = os.getenv("AZURE_FIREWALL_POLICY").strip('"')

    extract_firewall_rules(tenant_id, client_id, client_secret, subscription_id, resource_group, policy_name)