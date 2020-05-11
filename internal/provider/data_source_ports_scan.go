package provider

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	scanner "github.com/picatz/terraform-provider-port-scan/internal/provider/port-scanner"
	"golang.org/x/crypto/ssh"
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
			"ports": {
				ForceNew: true,
				Optional: true,
				Type:     schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeInt,
				},
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
			// Optional SSH Bastion
			"ssh_bastion": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"ip_address": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "SSH bastion IP address",
						},
						"port": {
							Type:        schema.TypeInt,
							Default:     22,
							Optional:    true,
							Description: "SSH port",
						},
						"user": {
							Type:        schema.TypeString,
							Default:     "root",
							Optional:    true,
							Description: "SSH username",
						},
						"password": {
							Type:        schema.TypeString,
							Sensitive:   true,
							Optional:    true,
							Description: "SSH password",
						},
						"private_key": {
							Type:        schema.TypeString,
							Sensitive:   true,
							Optional:    true,
							Description: "PEM encoded SSH private key",
						},
					},
				},
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
		ports     []int
	)

	// First, grab the require IP address
	ipAddress = d.Get("ip_address").(string)

	// check port options, for single or range
	port, ok := d.GetOk("port")
	if ok {
		fromPort = port.(int)
		toPort = port.(int)
	} else {
		// using range
		if portsConfig, ok := d.GetOk("ports"); ok {
			if portIfaceSlice, ok := portsConfig.([]interface{}); ok {
				ports = convertIntArr(portIfaceSlice)
			}
		} else {
			fromPort = d.Get("from_port").(int)
			toPort = d.Get("to_port").(int)
		}
	}

	// default dialer
	var dialer scanner.Dialer = scanner.DefaultDialer
	defer dialer.Close()

	// check if using SSH bastion
	if _, ok := d.GetOk("ssh_bastion"); ok {
		var (
			bastionConnectTimeout time.Duration = 2 * time.Minute
			bastionUser           string        = d.Get("ssh_bastion.0.user").(string)
			bastionAddress        string        = fmt.Sprintf(
				"%s:%d",
				d.Get("ssh_bastion.0.ip_address").(string),
				d.Get("ssh_bastion.0.port").(int),
			)
			sshClientConfig *ssh.ClientConfig = &ssh.ClientConfig{
				Timeout: bastionConnectTimeout,
				User:    bastionUser,
				Auth:    []ssh.AuthMethod{},
				// TODO(kent): don't use insecure ignore host key...
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}
		)

		// if using ssh key
		if _, ok := d.GetOk("ssh_bastion.0.private_key"); ok {
			pemEncodedPrivateKey := d.Get("ssh_bastion.0.private_key").(string)
			authMethod, err := sshKey(pemEncodedPrivateKey)
			if err != nil {
				return err
			}
			sshClientConfig.Auth = append(sshClientConfig.Auth, authMethod)
		} else { // using password
			if _, ok := d.GetOk("ssh_bastion.0.password"); ok {
				sshClientConfig.Auth = append(sshClientConfig.Auth, ssh.Password(d.Get("ssh_bastion.0.password").(string)))
			} else { // no idea what we're using
				return fmt.Errorf("no SSH private_key or password provided")
			}
		}

		sshDialer, err := scanner.NewSSHBastionScanner(bastionAddress, sshClientConfig)
		if err != nil {
			return err
		}

		dialer = sshDialer
	}

	openPorts := []int{}

	if len(ports) > 0 {
		for _, port := range ports {
			for result := range scanner.Run(dialer, ipAddress, port, port, scanner.DefaultTimeoutPerPort) {
				if result.Open {
					openPorts = append(openPorts, result.Port)
				}
			}
		}
	} else {
		for result := range scanner.Run(dialer, ipAddress, fromPort, toPort, scanner.DefaultTimeoutPerPort) {
			if result.Open {
				openPorts = append(openPorts, result.Port)
			}
		}

	}

	return d.Set("open_ports", openPorts)
}

func sshKey(key string) (ssh.AuthMethod, error) {
	var trimmedKey string

	bufioScanner := bufio.NewScanner(bytes.NewReader([]byte(key)))
	for bufioScanner.Scan() {
		if len(bufioScanner.Bytes()) > 0 {
			trimmedKey += strings.TrimSpace(bufioScanner.Text()) + "\n"
		}
	}

	signer, err := ssh.ParsePrivateKey([]byte(trimmedKey))
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(signer), nil
}

func convertIntArr(ifaceArr []interface{}) []int {
	var arr []int
	for _, v := range ifaceArr {
		if v == nil {
			continue
		}
		arr = append(arr, v.(int))
	}
	return arr
}
