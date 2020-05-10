package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/plugin"
	"github.com/picatz/terraform-provider-port-scan/internal/provider"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{ProviderFunc: provider.New})
}
