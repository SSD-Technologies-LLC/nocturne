package dht

import (
	"fmt"
	"testing"
	"time"
)

// knowledgeCluster creates n DHT nodes and connects them in a chain: 0→1→2→...
func knowledgeCluster(t *testing.T, n int) []*Node {
	t.Helper()
	nodes := testNodes(t, n) // reuse existing helper
	// Connect nodes in a chain: 0→1→2→...
	for i := 1; i < len(nodes); i++ {
		_, err := nodes[i-1].Ping(nodes[i].Addr())
		if err != nil {
			t.Fatalf("ping node %d→%d: %v", i-1, i, err)
		}
	}
	time.Sleep(100 * time.Millisecond) // let connections settle
	return nodes
}

func makeEntry(id, domain, content string, confidence float64) *KnowledgeEntry {
	return &KnowledgeEntry{
		ID:         id,
		AgentID:    "agent-1",
		OperatorID: "op-1",
		Type:       "fact",
		Domain:     domain,
		Content:    content,
		Confidence: confidence,
		CreatedAt:  time.Now().Unix(),
		Signature:  "test-sig",
	}
}

func TestPublishAndQueryKnowledge(t *testing.T) {
	nodes := knowledgeCluster(t, 3)
	a, b := nodes[0], nodes[1]

	entry := makeEntry("entry-1", "security", "AES-256 is a symmetric cipher", 0.95)

	// Publish on node A.
	if err := a.PublishKnowledge(entry); err != nil {
		t.Fatalf("PublishKnowledge: %v", err)
	}

	// Allow time for DHT replication.
	time.Sleep(200 * time.Millisecond)

	// Query on node B.
	results, err := b.QueryKnowledge("security", "", 0, 0)
	if err != nil {
		t.Fatalf("QueryKnowledge: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ID != "entry-1" {
		t.Fatalf("expected entry ID 'entry-1', got %q", results[0].ID)
	}
	if results[0].Content != "AES-256 is a symmetric cipher" {
		t.Fatalf("unexpected content: %q", results[0].Content)
	}
}

func TestQueryKnowledgeWithTextFilter(t *testing.T) {
	nodes := knowledgeCluster(t, 3)
	a, b := nodes[0], nodes[1]

	entries := []*KnowledgeEntry{
		makeEntry("e1", "crypto", "AES-256 is a symmetric cipher", 0.9),
		makeEntry("e2", "crypto", "RSA is an asymmetric algorithm", 0.85),
		makeEntry("e3", "crypto", "SHA-256 produces a 256-bit hash", 0.92),
	}

	for _, e := range entries {
		if err := a.PublishKnowledge(e); err != nil {
			t.Fatalf("PublishKnowledge(%s): %v", e.ID, err)
		}
	}

	time.Sleep(200 * time.Millisecond)

	// Query with text filter "hash" — should match only e3.
	results, err := b.QueryKnowledge("crypto", "hash", 0, 0)
	if err != nil {
		t.Fatalf("QueryKnowledge: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result matching 'hash', got %d", len(results))
	}
	if results[0].ID != "e3" {
		t.Fatalf("expected entry 'e3', got %q", results[0].ID)
	}

	// Query with text filter "algorithm" — should match only e2.
	results, err = b.QueryKnowledge("crypto", "algorithm", 0, 0)
	if err != nil {
		t.Fatalf("QueryKnowledge: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result matching 'algorithm', got %d", len(results))
	}
	if results[0].ID != "e2" {
		t.Fatalf("expected entry 'e2', got %q", results[0].ID)
	}
}

func TestQueryKnowledgeWithConfidenceFilter(t *testing.T) {
	nodes := knowledgeCluster(t, 3)
	a, b := nodes[0], nodes[1]

	entries := []*KnowledgeEntry{
		makeEntry("c1", "math", "Pi is approximately 3.14159", 0.99),
		makeEntry("c2", "math", "E is approximately 2.71828", 0.75),
		makeEntry("c3", "math", "Golden ratio is about 1.618", 0.50),
	}

	for _, e := range entries {
		if err := a.PublishKnowledge(e); err != nil {
			t.Fatalf("PublishKnowledge(%s): %v", e.ID, err)
		}
	}

	time.Sleep(200 * time.Millisecond)

	// Filter by min confidence 0.80 — should return only c1.
	results, err := b.QueryKnowledge("math", "", 0.80, 0)
	if err != nil {
		t.Fatalf("QueryKnowledge: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result with confidence >= 0.80, got %d", len(results))
	}
	if results[0].ID != "c1" {
		t.Fatalf("expected entry 'c1', got %q", results[0].ID)
	}

	// Filter by min confidence 0.60 — should return c1 and c2.
	results, err = b.QueryKnowledge("math", "", 0.60, 0)
	if err != nil {
		t.Fatalf("QueryKnowledge: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results with confidence >= 0.60, got %d", len(results))
	}
}

func TestQueryKnowledgeWithLimit(t *testing.T) {
	nodes := knowledgeCluster(t, 3)
	a, b := nodes[0], nodes[1]

	for i := 0; i < 5; i++ {
		entry := makeEntry(
			fmt.Sprintf("lim-%d", i),
			"bulk",
			fmt.Sprintf("Entry number %d", i),
			0.90,
		)
		if err := a.PublishKnowledge(entry); err != nil {
			t.Fatalf("PublishKnowledge(lim-%d): %v", i, err)
		}
	}

	time.Sleep(200 * time.Millisecond)

	// Query with limit=2.
	results, err := b.QueryKnowledge("bulk", "", 0, 2)
	if err != nil {
		t.Fatalf("QueryKnowledge: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results with limit=2, got %d", len(results))
	}
}

func TestDeleteKnowledge(t *testing.T) {
	nodes := knowledgeCluster(t, 3)
	a, b := nodes[0], nodes[1]

	entry := makeEntry("del-1", "ephemeral", "Temporary knowledge", 0.85)
	if err := a.PublishKnowledge(entry); err != nil {
		t.Fatalf("PublishKnowledge: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Verify it exists.
	results, err := b.QueryKnowledge("ephemeral", "", 0, 0)
	if err != nil {
		t.Fatalf("QueryKnowledge before delete: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result before delete, got %d", len(results))
	}

	// Delete the entry from node A.
	if err := a.DeleteKnowledge("del-1", "ephemeral"); err != nil {
		t.Fatalf("DeleteKnowledge: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Query again — should return empty since the entry was removed from domain index.
	results, err = a.QueryKnowledge("ephemeral", "", 0, 0)
	if err != nil {
		t.Fatalf("QueryKnowledge after delete: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results after delete, got %d", len(results))
	}
}

func TestQueryKnowledgeEmptyDomain(t *testing.T) {
	nodes := knowledgeCluster(t, 3)
	b := nodes[1]

	// Query a domain that has no entries.
	results, err := b.QueryKnowledge("nonexistent-domain", "", 0, 0)
	if err != nil {
		t.Fatalf("QueryKnowledge on empty domain: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil results for empty domain, got %d entries", len(results))
	}
}

func TestPublishKnowledgeDeduplicate(t *testing.T) {
	nodes := knowledgeCluster(t, 3)
	a := nodes[0]

	entry := makeEntry("dup-1", "dedup", "Some knowledge", 0.90)

	// Publish the same entry twice.
	if err := a.PublishKnowledge(entry); err != nil {
		t.Fatalf("PublishKnowledge (1st): %v", err)
	}
	if err := a.PublishKnowledge(entry); err != nil {
		t.Fatalf("PublishKnowledge (2nd): %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Query — should return exactly one entry, not two.
	results, err := a.QueryKnowledge("dedup", "", 0, 0)
	if err != nil {
		t.Fatalf("QueryKnowledge: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result after duplicate publish, got %d", len(results))
	}
	if results[0].ID != "dup-1" {
		t.Fatalf("expected entry 'dup-1', got %q", results[0].ID)
	}
}
