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

```console
git clone https://github.com/picatz/terraform-provider-port-scan.git
cd terraform-provider-port-scan
make build
```

After the build is complete, if your terraform running folder does not match your GOPATH environment, you need to copy the `terraform-provider-port` executable to your running folder and re-run `terraform init` to make terraform aware of your local provider executable.
