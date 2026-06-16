package config

import "testing"

func TestPhase6EnvValidation(t *testing.T) {
	c := Defaults()
	if c.App.Env != "development" {
		t.Fatal(c.App.Env)
	}
	c.App.Env = "bogus"
	if Validate(c) == nil {
		t.Fatal("invalid env should fail")
	}
}
func TestProductionDevKeyFailsAndEnvKeySucceeds(t *testing.T) {
	c := Defaults()
	c.App.Env = "production"
	c.Security.APIKeyEnabled = true
	if Validate(c) == nil {
		t.Fatal("dev key must fail production")
	}
	c.Security.APIKeys = []string{"real-secret"}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
}
func TestUnsafeOverrideAllowsProduction(t *testing.T) {
	c := Defaults()
	c.App.Env = "production"
	c.Security.ProtectManagementAPI = false
	c.UnsafeProduction = true
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
}
func TestCloudflareVerifyJWTFails(t *testing.T) {
	c := Defaults()
	c.CloudflareAccess.VerifyJWT = true
	if Validate(c) == nil {
		t.Fatal("verify_jwt should fail until implemented")
	}
}
func TestProductionWildcardCORSFails(t *testing.T) {
	c := Defaults()
	c.App.Env = "production"
	c.Security.APIKeyEnabled = true
	c.Security.APIKeys = []string{"real"}
	c.CORS.Enabled = true
	c.CORS.AllowedOrigins = []string{"*"}
	if Validate(c) == nil {
		t.Fatal("wildcard CORS should fail")
	}
	c.UnsafeProduction = true
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
}
