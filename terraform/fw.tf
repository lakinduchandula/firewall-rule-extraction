resource "azurerm_firewall_policy" "child_spk_policy" {
  name                = "child-spk-policy"
  resource_group_name = azurerm_resource_group.fw-auto-rg.name
  location            = azurerm_resource_group.fw-auto-rg.location
}


resource "azurerm_firewall_policy_rule_collection_group" "example" {
  name               = "fwpolicy-rcg"
  firewall_policy_id = azurerm_firewall_policy.child_spk_policy.id
  priority           = 500
  # Application Rule Collection with destination_fqdns
  application_rule_collection {
    name     = "app_rule_collection1"
    priority = 100
    action   = "Allow"
    rule {
      name = "app_rule1"
      protocols {
        type = "Http"
        port = 80
      }
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = ["10.0.0.1"]
      destination_fqdns = ["*.microsoft.com", "*.example.com"]
    }
  }

  # Application Rule Collection with fqdn_tags
  application_rule_collection {
    name     = "app_rule_collection2"
    priority = 200
    action   = "Deny"
    rule {
      name = "app_rule2"
      protocols {
        type = "Https"
        port = 8443
      }
      source_addresses      = ["192.168.1.0/24"]
      destination_fqdn_tags = ["WindowsUpdate", "AzureBackup"]
    }
  }

  # Network Rule Collection
  network_rule_collection {
    name     = "network_rule_collection1"
    priority = 300
    action   = "Allow"
    rule {
      name                  = "network_rule1"
      protocols             = ["TCP"]
      source_addresses      = ["10.0.0.1", "10.0.0.2"]
      destination_addresses = ["192.168.1.1", "192.168.1.2"]
      destination_ports     = ["80", "443"]
    }
    rule {
      name                  = "network_rule2"
      protocols             = ["UDP"]
      source_addresses      = ["172.16.0.0/16"]
      destination_addresses = ["10.0.0.0/24"]
      destination_ports     = ["53"]
    }
  }

  # NAT Rule Collection
  nat_rule_collection {
    name     = "nat_rule_collection1"
    priority = 400
    action   = "Dnat"
    rule {
      name                = "nat_rule1"
      protocols           = ["TCP"]
      source_addresses    = ["10.0.0.1"]
      destination_address = "192.168.1.1"
      destination_ports   = ["80"]
      translated_address  = "192.168.0.1"
      translated_port     = "8080"
    }
    rule {
      name                = "nat_rule2"
      protocols           = ["UDP"]
      source_addresses    = ["10.0.0.2"]
      destination_address = "192.168.1.2"
      destination_ports   = ["53"]
      translated_address  = "192.168.0.2"
      translated_port     = "5353"
    }
  }
}