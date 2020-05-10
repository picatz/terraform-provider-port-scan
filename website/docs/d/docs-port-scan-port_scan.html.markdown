---
layout: "port-scan"
page_title: "Port Scan: port_scan"
sidebar_current: "docs-port-scan-port_scan"
description: |-
  Port scan data source.
---

# port_scan

Performs port scan to report open ports.

## Example Usage

```hcl
data "ports_scan" "example" {
  ip_address = "127.0.0.1"
  port       = 22
}
```

## Attributes Reference

* `ip_address` - IP address attribute.
* `port` - Single port attribute.
* `from_port` - Range start port attribute.
* `to_port` - Range end port attribute.
* `open_ports` - Computed attributed for open ports.
