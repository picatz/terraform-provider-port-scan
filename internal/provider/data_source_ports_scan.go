package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	scanner "github.com/picatz/terraform-provider-port-scan/internal/provider/port-scanner"
)

func dataSourcePortScan() *schema.Resource {
	return &schema.Resource{
		Read: dataSourcePortScanRead,
		Schema: map[string]*schema.Schema{
			"ip_address": {
				ForceNew: true,
				Required: true,
				Type:     schema.TypeString,
			},
			"port": {
				ForceNew: true,
				Optional: true,
				Type:     schema.TypeInt,
			},
			"from_port": {
				ForceNew: true,
				Optional: true,
				Type:     schema.TypeInt,
				Default:  1,
			},
			"to_port": {
				ForceNew: true,
				Optional: true,
				Type:     schema.TypeInt,
				Default:  1024,
			},
			// Computed fields
			"open_ports": {
				Computed: true,
				Type:     schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeInt,
				},
			},
		},
	}
}

func dataSourcePortScanRead(d *schema.ResourceData, meta interface{}) error {
	// Note: this took me FOREVER to figure out I needed to set an ID...
	//       so everything would seemingly almost work, but the attributes
	//       would never get set!
	d.SetId("-")

	var (
		ipAddress string
		fromPort  int
		toPort    int
	)

	// First, grab the require IP address
	ipAddress = d.Get("ip_address").(string)

	// check port options, for single or range
	port, ok := d.GetOk("port")
	if ok {
		fromPort = port.(int)
		toPort = port.(int)
	} else { // using range
		fromPort = d.Get("from_port").(int)
		toPort = d.Get("to_port").(int)
	}

	// default dialer
	var dialer scanner.Dialer = scanner.DefaultDialer
	defer dialer.Close()

	openPorts := []int{}

	for result := range scanner.Run(dialer, ipAddress, fromPort, toPort, scanner.DefaultTimeoutPerPort) {
		if result.Open {
			openPorts = append(openPorts, result.Port)
		}
	}

	return d.Set("open_ports", openPorts)
}

func sshKey(key string) (ssh.AuthMethod, error) {
	signer, err := ssh.ParsePrivateKey([]byte(key))
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(signer), nil
}
