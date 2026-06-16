package config

import (
	"gopkg.in/yaml.v3"
	"os"
)

func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		path = os.Getenv("OPENAUDIT_CONFIG")
	}
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	err = yaml.Unmarshal(b, &cfg)
	fill(&cfg)
	return cfg, err
}
func fill(c *Config) {
	d := Defaults()
	if c.Server.Addr == "" {
		c.Server.Addr = d.Server.Addr
	}
	if c.Server.ReadTimeoutSeconds == 0 {
		c.Server.ReadTimeoutSeconds = d.Server.ReadTimeoutSeconds
	}
	if c.Server.WriteTimeoutSeconds == 0 {
		c.Server.WriteTimeoutSeconds = d.Server.WriteTimeoutSeconds
	}
	if c.Rules.DataDir == "" {
		c.Rules.DataDir = d.Rules.DataDir
	}
	if c.Admin.Path == "" {
		c.Admin.Path = d.Admin.Path
	}
	if len(c.Security.APIKeys) == 0 {
		c.Security.APIKeys = d.Security.APIKeys
	}
	if len(c.Security.ProtectedPaths) == 0 {
		c.Security.ProtectedPaths = d.Security.ProtectedPaths
	}
	if c.AuditLog.Path == "" {
		c.AuditLog.Path = d.AuditLog.Path
	}
	if c.AuditLog.MaxEntries == 0 {
		c.AuditLog.MaxEntries = d.AuditLog.MaxEntries
	}
	if c.Limits.MaxTextRunes == 0 {
		c.Limits.MaxTextRunes = d.Limits.MaxTextRunes
	}
	if c.Limits.MaxBatchItems == 0 {
		c.Limits.MaxBatchItems = d.Limits.MaxBatchItems
	}
	if c.Limits.MaxHits == 0 {
		c.Limits.MaxHits = d.Limits.MaxHits
	}
}
