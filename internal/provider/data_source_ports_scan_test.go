package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	r "github.com/hashicorp/terraform-plugin-sdk/helper/resource"
)

const testDataSourceUnknownKeyError = `
data "port_scan" "example" {
	this_doesnt_exist = "foo"
}
`

/*
config is invalid: 2 problems:

        - Missing required argument: The argument "ip_address" is required, but no definition was found.
        - Unsupported argument: An argument named "this_doesnt_exist" is not expected here.
*/

func TestDataSource_compileUnknownKeyError(t *testing.T) {
	r.UnitTest(t, resource.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			{
				Config:      testDataSourceUnknownKeyError,
				ExpectError: regexp.MustCompile(`- Missing required argument: The argument "ip_address" is required, but no definition was found.`),
			},
			{
				Config:      testDataSourceUnknownKeyError,
				ExpectError: regexp.MustCompile(`- Unsupported argument: An argument named "this_doesnt_exist" is not expected here.`),
			},
		},
	})
}

const testDataSourceLocalhost5959 = `
data "port_scan" "example" {
	ip_address = "127.0.0.1"
	port       = 5959
}
`

func TestDataSource_compileLocalhost5959(t *testing.T) {
	r.UnitTest(t, resource.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			{
				Config: testDataSourceLocalhost5959,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.ports_scan.example", "ip_address", "127.0.0.1"),
					resource.TestCheckResourceAttr("data.ports_scan.example", "port", "5959"),
				),
			},
		},
	})
}
