---
layout: "port-scan"
page_title: "Provider: Port Scan"
sidebar_current: "docs-port-scan-index"
description: |-
  Terraform provider port-scan.
---

# Port Scan Provider

Terraform Provider for performing a TCP connect-based port scans.

## Example Usage

```hcl
data "port_scan" "example" {
  ip_address = "127.0.0.1"
  from_port  = 1
  to_port    = 65535
}

output "open_ports" {
  value = data.port_scan.example.open_ports
}
```
