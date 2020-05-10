package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

var testProvider *schema.Provider
var testProviders map[string]terraform.ResourceProvider

func init() {
	testProvider = New().(*schema.Provider)
	testProviders = map[string]terraform.ResourceProvider{
		"ports": testProvider,
	}
}

func TestNew(t *testing.T) {
	if err := New().(*schema.Provider).InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}
