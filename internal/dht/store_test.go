package dht

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func TestLocalStorePutGet(t *testing.T) {
	s, err := NewLocalStore(":memory:")
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer s.Close()

	key := ContentKey("test", "entry1")
	value := []byte(`{"data":"hello world"}`)

	if err := s.Put(key, value, 1*time.Hour); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, found, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatal("expected found=true, got false")
	}
	if string(got) != string(value) {
		t.Fatalf("Get returned %q, want %q", got, value)
	}
}

func TestLocalStoreGetNotFound(t *testing.T) {
	s, err := NewLocalStore(":memory:")
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer s.Close()

	key := ContentKey("test", "nonexistent")
	got, found, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Fatal("expected found=false for nonexistent key")
	}
	if got != nil {
		t.Fatalf("expected nil value, got %v", got)
	}
}

func TestLocalStoreDelete(t *testing.T) {
	s, err := NewLocalStore(":memory:")
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer s.Close()

	key := ContentKey("test", "to-delete")
	value := []byte(`{"delete":"me"}`)

	if err := s.Put(key, value, 1*time.Hour); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Verify it exists.
	_, found, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get before delete: %v", err)
	}
	if !found {
		t.Fatal("expected entry to exist before delete")
	}

	// Delete it.
	if err := s.Delete(key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Verify it's gone.
	_, found, err = s.Get(key)
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if found {
		t.Fatal("expected found=false after delete")
	}
}

func TestLocalStoreTTLExpiry(t *testing.T) {
	s, err := NewLocalStore(":memory:")
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer s.Close()

	key := ContentKey("test", "expiring")
	value := []byte(`{"ttl":"short"}`)

	// Put with a very short TTL (1ms).
	if err := s.Put(key, value, 1*time.Millisecond); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Sleep to let the entry expire.
	time.Sleep(50 * time.Millisecond)

	got, found, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Fatal("expected found=false for expired entry")
	}
	if got != nil {
		t.Fatalf("expected nil value for expired entry, got %v", got)
	}
}

func TestLocalStorePruneExpired(t *testing.T) {
	s, err := NewLocalStore(":memory:")
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer s.Close()

	// Insert 5 entries with very short TTL.
	for i := 0; i < 5; i++ {
		key := ContentKey("prune", string(rune('a'+i)))
		value := []byte(`{"i":"` + string(rune('a'+i)) + `"}`)
		if err := s.Put(key, value, 1*time.Millisecond); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}

	// Insert 2 entries with long TTL.
	for i := 0; i < 2; i++ {
		key := ContentKey("keep", string(rune('a'+i)))
		value := []byte(`{"keep":"yes"}`)
		if err := s.Put(key, value, 1*time.Hour); err != nil {
			t.Fatalf("Put keep %d: %v", i, err)
		}
	}

	// Sleep to let the short-TTL entries expire.
	time.Sleep(50 * time.Millisecond)

	pruned, err := s.PruneExpired()
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if pruned != 5 {
		t.Fatalf("PruneExpired returned %d, want 5", pruned)
	}

	// Verify the long-TTL entries still exist.
	keys, err := s.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("ListKeys returned %d keys, want 2", len(keys))
	}
}

func TestLocalStoreListKeys(t *testing.T) {
	s, err := NewLocalStore(":memory:")
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer s.Close()

	// Insert several entries.
	expected := make(map[NodeID]bool)
	for i := 0; i < 5; i++ {
		key := ContentKey("list", string(rune('a'+i)))
		value := []byte(`{"list":"test"}`)
		if err := s.Put(key, value, 1*time.Hour); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
		expected[key] = true
	}

	keys, err := s.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 5 {
		t.Fatalf("ListKeys returned %d keys, want 5", len(keys))
	}

	for _, k := range keys {
		if !expected[k] {
			t.Fatalf("unexpected key in ListKeys result: %x", k[:4])
		}
	}
}

func TestNodeStoreAndFindValue(t *testing.T) {
	// Create 3 nodes: A, B, C. Connect A->B->C.
	nodes := testNodes(t, 3)
	a, b, c := nodes[0], nodes[1], nodes[2]

	// A pings B.
	if _, err := a.Ping(b.Addr()); err != nil {
		t.Fatalf("A ping B: %v", err)
	}
	// B pings C.
	if _, err := b.Ping(c.Addr()); err != nil {
		t.Fatalf("B ping C: %v", err)
	}

	// Wait for routing tables to stabilize.
	waitForTableSize(t, a, 1, 2*time.Second)
	waitForTableSize(t, b, 2, 2*time.Second)
	waitForTableSize(t, c, 1, 2*time.Second)

	// A stores a value.
	key := ContentKey("agent-knowledge", "test-entry-1")
	value := []byte(`{"knowledge":"distributed mesh data"}`)

	if err := a.Store(key, value); err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Give STORE RPCs a moment to propagate.
	time.Sleep(200 * time.Millisecond)

	// C should be able to FindValue through the network.
	got, err := c.FindValue(key)
	if err != nil {
		t.Fatalf("FindValue: %v", err)
	}
	if got == nil {
		t.Fatal("FindValue returned nil, expected value")
	}

	// Compare the value contents.
	var original, retrieved json.RawMessage
	if err := json.Unmarshal(value, &original); err != nil {
		t.Fatalf("unmarshal original: %v", err)
	}
	if err := json.Unmarshal(got, &retrieved); err != nil {
		t.Fatalf("unmarshal retrieved: %v", err)
	}
	if string(original) != string(retrieved) {
		t.Fatalf("FindValue returned %q, want %q", retrieved, original)
	}
}

func TestNodeFindValueNotFound(t *testing.T) {
	// Create 2 nodes.
	nodes := testNodes(t, 2)
	a, b := nodes[0], nodes[1]

	// A pings B so they know each other.
	if _, err := a.Ping(b.Addr()); err != nil {
		t.Fatalf("A ping B: %v", err)
	}
	waitForTableSize(t, a, 1, 2*time.Second)

	// FindValue for a key that was never stored.
	key := ContentKey("never", "stored")
	got, err := a.FindValue(key)
	if err != nil {
		t.Fatalf("FindValue: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil value for non-existent key, got %q", got)
	}
}

// testNodes is defined in node_test.go — it creates n DHT nodes, each
// listening on a random port. We rely on it being in the same package.
// The helper also uses ed25519.GenerateKey and the Config/NewNode/Start pattern.
// We need to verify testNodes still works after adding StorePath to Config
// (it should, since StorePath defaults to "" which triggers :memory:).

func TestLocalStoreOverwrite(t *testing.T) {
	// Verify that Put with the same key overwrites the value.
	s, err := NewLocalStore(":memory:")
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer s.Close()

	key := ContentKey("test", "overwrite")
	v1 := []byte(`{"version":1}`)
	v2 := []byte(`{"version":2}`)

	if err := s.Put(key, v1, 1*time.Hour); err != nil {
		t.Fatalf("Put v1: %v", err)
	}
	if err := s.Put(key, v2, 1*time.Hour); err != nil {
		t.Fatalf("Put v2: %v", err)
	}

	got, found, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if string(got) != string(v2) {
		t.Fatalf("expected %q, got %q", v2, got)
	}
}

// Ensure testNodes helper compiles with the unused import suppression.
var _ = func() {
	_ = ed25519.PublicKeySize
	_ = rand.Reader
}
