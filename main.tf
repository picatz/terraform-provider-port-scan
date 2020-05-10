data "port_scan" "example" {
  ip_address = "127.0.0.1"
  port       = 5959
}

output "open_ports" {
  value = data.port_scan.example.open_ports
}