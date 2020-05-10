# Terraform Provider Port Scan

Terraform Provider for performing TCP connect-based port scans.

## Example

```hcl
data "port_scan" "example" {
  ip_address = "127.0.0.1"
  port       = 5959
}

output "open_ports" {
  value = data.port_scan.example.open_ports
}
```

## Building the Provider

The following steps will create a `terraform-provider-port` executable:

```console
git clone https://github.com/picatz/terraform-provider-port-scan.git
cd terraform-provider-port-scan
make build
```

After the build is complete, you will need to copy the `terraform-provider-port` executable over and re-run `terraform init` to make Terraform aware of your local provider executable.
