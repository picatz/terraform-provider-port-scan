# Terraform Provider Port Scan

Terraform Provider for performing TCP connect-based port scans.

## Example

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

```console
$ terraform plan
...
data.port_scan.example: Refreshing state...
...
```

```console
$ terraform apply
...

Outputs:

open_ports = []
```

## SSH Bastion Support

When the hosts aren't publicly available, we can use an SSH bastion jump-box for port scanning.

For example, after using the [`picatz/terraform-google-nomad`](https://github.com/picatz/terraform-google-nomad) provider, we can verify the Nomad server (`192.168.2.2`) is up through the SSH bastion:

```hcl
data "port_scan" "nomad_server" {
  ip_address = "192.168.2.2"
  ports = [
    22,
    4648,
    4647,
    4646,
  ]

  ssh_bastion {
    user        = "ubuntu"
    ip_address  = "34.75.85.111"
    private_key = file("private_key.pem")

    insecure_ignore_host_key = true
  }
}

output "open_ports" {
  value = data.port_scan.nomad_server.open_ports
}
```

> **Note**: Try to use single ports (or small port ranges), as large port scan ranges will take a long time, since the connect timeout to the internal IP address is controlled by the SSH bastion server itself. To speed this up requires using a custom SSH server that adds a small (or configurable) timeout to the `direct-tcpip` channel type. A configurable timeout may break other SSH server's assumptions about the channel open direct message described in [`RFC 4254 7.2`](https://tools.ietf.org/html/rfc4254#section-7.2).

## Building the Provider

The following steps will create a `terraform-provider-port` executable:

```console
git clone https://github.com/picatz/terraform-provider-port-scan.git
cd terraform-provider-port-scan
make build
```

After the build is complete, you will need to copy the `terraform-provider-port` executable over and re-run `terraform init` to make Terraform aware of your local provider executable.
