import os
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient

load_dotenv()

tenant_id = os.getenv("AZURE_TENANT_ID")
client_id = os.getenv("AZURE_CLIENT_ID")
client_secret = os.getenv("AZURE_CLIENT_SECRET")
subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
resource_group_name = os.getenv("AZURE_RESOURCE_GROUP")
firewall_policy_name = os.getenv("AZURE_FIREWALL_POLICY")

credential = ClientSecretCredential(tenant_id, client_id, client_secret)

network_client = NetworkManagementClient(credential, subscription_id)

rule_collection_groups = network_client.firewall_policy_rule_collection_groups.list(
    resource_group_name, firewall_policy_name
)

# Iterate and extract rules
for rule_group in rule_collection_groups:
    print(f"Rule Collection Group: {rule_group.name}")
    
    for rule_collection in rule_group.rule_collections:
        print(f"  Rule Collection: {rule_collection.name} (Type: {rule_collection.rule_collection_type})")
        
        # for rule in rule_collection.rules:
        #     print(f"    Rule Name: {rule.name}")
        #     print(f"    Rule Action: {rule.action.type}")
        #     print(f"    Rule Priority: {getattr(rule, 'priority', 'N/A')}")
        #     print(f"    Rule Destinations: {getattr(rule, 'destination_addresses', 'N/A')}")
        #     print("-" * 50)
