package ml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/C0oki3s/veilgate/internal/rules"
)

func buildMinerConfig(minSupport int, minPost, autoPromote float64) *rules.Holder[rules.ML] {
	m := &rules.ML{Enabled: true}
	m.Miner.Enabled = true
	m.Miner.MinSupport = minSupport
	m.Miner.MinPosterior = minPost
	m.Miner.AutoPromoteConfidence = autoPromote
	m.Miner.WritePath = "learned.yaml"
	return rules.NewHolder(m)
}

func TestMinerWritesCandidatesAboveThreshold(t *testing.T) {
	dir := t.TempDir()

	b := NewBayes(1.0)
	// Drive a strong agent signal on one bucket.
	agent := Vec{Categorical: []Feature{{Name: "ua", Bucket: "nikto"}}}
	for i := 0; i < 50; i++ {
		b.Update(agent, "agent")
	}
	// And a benign bucket that should be filtered out by the posterior gate.
	human := Vec{Categorical: []Feature{{Name: "ua", Bucket: "firefox"}}}
	for i := 0; i < 50; i++ {
		b.Update(human, "human")
	}

	m := NewMiner(b, buildMinerConfig(10, 0.9, 0), nil, dir)
	if err := m.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "learned.yaml"))
	if err != nil {
		t.Fatalf("read learned.yaml: %v", err)
	}
	if !strings.Contains(string(data), "nikto") {
		t.Fatalf("learned.yaml missing agent bucket:\n%s", string(data))
	}
	if strings.Contains(string(data), "firefox") {
		t.Fatalf("learned.yaml should have filtered out human bucket:\n%s", string(data))
	}

	var doc rules.Learned
	// Trim header comment — yaml.Unmarshal handles it but verify parse round-trip.
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse learned.yaml: %v", err)
	}
	if len(doc.Candidates) == 0 {
		t.Fatalf("expected at least one candidate")
	}
	for _, c := range doc.Candidates {
		if c.Active {
			t.Fatalf("auto-promote disabled but got active candidate %+v", c)
		}
	}
}

func TestMinerPreservesOperatorActiveFlag(t *testing.T) {
	dir := t.TempDir()
	// Pre-seed learned.yaml with an active candidate.
	prior := rules.Learned{Candidates: []rules.LearnedCandidate{
		{Feature: "ua", Bucket: "nikto", Posterior: 0.99, Support: 100, Active: true},
	}}
	buf, _ := yaml.Marshal(&prior)
	if err := os.WriteFile(filepath.Join(dir, "learned.yaml"), buf, 0o644); err != nil {
		t.Fatal(err)
	}

	b := NewBayes(1.0)
	agent := Vec{Categorical: []Feature{{Name: "ua", Bucket: "nikto"}}}
	for i := 0; i < 30; i++ {
		b.Update(agent, "agent")
	}
	m := NewMiner(b, buildMinerConfig(5, 0.9, 0), nil, dir)
	if err := m.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "learned.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc rules.Learned
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range doc.Candidates {
		if c.Feature == "ua" && c.Bucket == "nikto" {
			found = true
			if !c.Active {
				t.Fatalf("operator-active flag was dropped on rewrite: %+v", c)
			}
		}
	}
	if !found {
		t.Fatalf("candidate missing after tick:\n%s", string(data))
	}
}

func TestMinerAutoPromoteAboveThreshold(t *testing.T) {
	dir := t.TempDir()
	b := NewBayes(1.0)
	agent := Vec{Categorical: []Feature{{Name: "ua", Bucket: "nikto"}}}
	for i := 0; i < 100; i++ {
		b.Update(agent, "agent")
	}
	m := NewMiner(b, buildMinerConfig(10, 0.9, 0.9), nil, dir)
	if err := m.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "learned.yaml"))
	var doc rules.Learned
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Candidates) == 0 || !doc.Candidates[0].Active {
		t.Fatalf("auto-promote did not mark candidate active: %+v", doc.Candidates)
	}
}

func TestMinerDisabledNoWrite(t *testing.T) {
	dir := t.TempDir()
	b := NewBayes(1.0)
	b.Update(Vec{Categorical: []Feature{{Name: "ua", Bucket: "x"}}}, "agent")

	m := &rules.ML{Enabled: true} // miner.enabled stays false
	holder := rules.NewHolder(m)
	mn := NewMiner(b, holder, nil, dir)
	if err := mn.Tick(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "learned.yaml")); !os.IsNotExist(err) {
		t.Fatalf("learned.yaml should not exist when miner disabled")
	}
}
