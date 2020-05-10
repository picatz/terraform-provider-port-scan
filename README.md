# Terraform Provider Ports Scan

Terraform Provider for performing a TCP connect-based port scans.

```hcl
data "ports_scan" "example" {
  ip_address = "127.0.0.1"
  port       = 5959
}

output "open_ports" {
  value = data.ports_scan.example.open_ports
}
```
