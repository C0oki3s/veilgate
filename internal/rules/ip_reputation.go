package rules

import (
	"fmt"
	"net"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// IPReputationCategory is one labelled CIDR bucket — "tor_exit",
// "cloud", "anonymizer", etc. Points is what scoreIPReputation adds
// when the client IP lands inside any of the category's CIDRs.
type IPReputationCategory struct {
	Name   string   `yaml:"name"`
	Points int      `yaml:"points"`
	CIDRs  []string `yaml:"cidrs"`

	// Parsed holds the compiled *net.IPNet form of CIDRs. Populated
	// lazily by the loader so downstream code doesn't re-parse on the
	// hot path. Field is excluded from YAML round-tripping.
	Parsed []*net.IPNet `yaml:"-"`
}

// IPReputationRotationTier mirrors the path_bruteforce tier shape: once
// the observed distinct IP count for a fingerprint meets DistinctIPs, the
// ip_rotation_fleet signal fires with the listed Points.
type IPReputationRotationTier struct {
	DistinctIPs int `yaml:"distinct_ips"`
	Points      int `yaml:"points"`
}

// IPReputation is the full YAML shape.
type IPReputation struct {
	Categories []IPReputationCategory `yaml:"categories"`

	FleetRotation struct {
		Enabled         bool                       `yaml:"enabled"`
		WindowSeconds   int                        `yaml:"window_seconds"`
		MaxFingerprints int                        `yaml:"max_fingerprints"`
		Tiers           []IPReputationRotationTier `yaml:"tiers"`
	} `yaml:"fleet_rotation"`

	UARotation struct {
		Enabled            bool `yaml:"enabled"`
		DistinctUAsForFire int  `yaml:"distinct_uas_for_fire"`
		Points             int  `yaml:"points"`
	} `yaml:"ua_rotation"`

	// PrivateCIDRs lists CIDR ranges considered non-routable (RFC1918,
	// loopback, link-local, CGNAT, ULA). An IP outside all of these is
	// "public". Loaded from the private_cidrs YAML key.
	PrivateCIDRs []string `yaml:"private_cidrs"`

	// ParsedPrivate is the compiled form of PrivateCIDRs. Populated by
	// the loader; excluded from YAML round-tripping.
	ParsedPrivate []*net.IPNet `yaml:"-"`
}

// LoadIPReputation reads ip_reputation.yaml from dir, merges community
// additions from rules/ip_reputation/, pre-parses every CIDR for fast
// lookup. Invalid CIDR entries are silently dropped so an operator typo
// in one category doesn't break the rest of the file.
func LoadIPReputation(dir string) (*IPReputation, error) {
	var ir IPReputation
	raw, err := readOptionalFromDir(dir, "ip_reputation.yaml")
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := yaml.Unmarshal(raw, &ir); err != nil {
			return nil, fmt.Errorf("parse ip_reputation.yaml: %w", err)
		}
	}
	// Merge community additions (new categories; append CIDRs by category name).
	if err := mergeIPReputationDir(filepath.Join(dir, "ip_reputation"), &ir); err != nil {
		return nil, err
	}
	for i := range ir.Categories {
		cat := &ir.Categories[i]
		for _, c := range cat.CIDRs {
			if _, n, err := net.ParseCIDR(c); err == nil {
				cat.Parsed = append(cat.Parsed, n)
				continue
			}
			if ip := net.ParseIP(c); ip != nil {
				mask := "/32"
				if ip.To4() == nil {
					mask = "/128"
				}
				if _, n, err := net.ParseCIDR(c + mask); err == nil {
					cat.Parsed = append(cat.Parsed, n)
				}
			}
		}
	}
	// Parse private CIDRs for IsPublicIP.
	for _, c := range ir.PrivateCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			ir.ParsedPrivate = append(ir.ParsedPrivate, n)
		}
	}
	return &ir, nil
}

// mergeIPReputationDir walks dir and merges community categories into ir.
// Scalar config (fleet_rotation, ua_rotation) is set only when the file
// carries non-zero values, so base.yaml sets them and community files
// (which omit scalars) never overwrite them. private_cidrs are appended.
func mergeIPReputationDir(dir string, ir *IPReputation) error {
	return walkYAMLDir(dir, func(path string, raw []byte) error {
		var patch IPReputation
		if err := yaml.Unmarshal(raw, &patch); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		// Scalars: only set when the file explicitly provides them.
		if patch.FleetRotation.WindowSeconds != 0 {
			ir.FleetRotation = patch.FleetRotation
		}
		if patch.UARotation.DistinctUAsForFire != 0 {
			ir.UARotation = patch.UARotation
		}
		// private_cidrs: append (community files may add private ranges).
		ir.PrivateCIDRs = append(ir.PrivateCIDRs, patch.PrivateCIDRs...)
		// Categories: merge by name.
		for _, pc := range patch.Categories {
			merged := false
			for i := range ir.Categories {
				if ir.Categories[i].Name == pc.Name {
					if pc.Points != 0 {
						ir.Categories[i].Points = pc.Points
					}
					ir.Categories[i].CIDRs = append(ir.Categories[i].CIDRs, pc.CIDRs...)
					merged = true
					break
				}
			}
			if !merged {
				ir.Categories = append(ir.Categories, pc)
			}
		}
		return nil
	})
}

// Classify returns the first matching category for the given IP, or
// ("", 0, false) if no category matches or ip is unparseable.
func (ir *IPReputation) Classify(ipStr string) (name string, points int, ok bool) {
	if ir == nil {
		return "", 0, false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", 0, false
	}
	for _, cat := range ir.Categories {
		for _, n := range cat.Parsed {
			if n.Contains(ip) {
				return cat.Name, cat.Points, true
			}
		}
	}
	return "", 0, false
}

// IsPublicIP returns true if ipStr is a routable public IP — i.e. it does
// not fall into any of the private_cidrs loaded from YAML. Returns false
// for unparseable strings or when no private CIDRs are configured.
func (ir *IPReputation) IsPublicIP(ipStr string) bool {
	if ir == nil || len(ir.ParsedPrivate) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range ir.ParsedPrivate {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}
