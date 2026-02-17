package dht

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDirectMessageDelivery(t *testing.T) {
	nodes := testNodes(t, 3)
	a, b, c := nodes[0], nodes[1], nodes[2]

	// Build a chain: a -> b -> c
	if _, err := a.Ping(b.Addr()); err != nil {
		t.Fatalf("a ping b: %v", err)
	}
	if _, err := b.Ping(c.Addr()); err != nil {
		t.Fatalf("b ping c: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	var received json.RawMessage
	done := make(chan struct{})

	c.OnDirectMessage(func(from NodeID, content json.RawMessage) {
		received = content
		close(done)
	})

	err := a.SendDirectMessage(c.ID(), json.RawMessage(`{"text":"hello C"}`))
	if err != nil {
		t.Fatalf("SendDirectMessage: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for direct message")
	}

	if string(received) != `{"text":"hello C"}` {
		t.Fatalf("unexpected content: %s", received)
	}
}

func TestDirectMessageDedup(t *testing.T) {
	nodes := testNodes(t, 2)
	a, b := nodes[0], nodes[1]

	// Connect a -> b.
	if _, err := a.Ping(b.Addr()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	count := 0
	done := make(chan struct{}, 10)

	b.OnDirectMessage(func(from NodeID, content json.RawMessage) {
		count++
		done <- struct{}{}
	})

	// Send a message.
	err := a.SendDirectMessage(b.ID(), json.RawMessage(`{"text":"hello"}`))
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	// Brief wait for any duplicates to arrive.
	time.Sleep(200 * time.Millisecond)

	if count != 1 {
		t.Fatalf("expected 1 delivery, got %d", count)
	}
}

func TestDirectMessageInboxFallback(t *testing.T) {
	nodes := testNodes(t, 3)
	a := nodes[0]

	// Connect the nodes so DHT Store works.
	if _, err := a.Ping(nodes[1].Addr()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if _, err := nodes[1].Ping(nodes[2].Addr()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Create a fake target not in the network.
	targetID := NodeID{0xFF, 0xFE, 0xFD}

	// Send should not error — it falls back to inbox.
	err := a.SendDirectMessage(targetID, json.RawMessage(`{"text":"to inbox"}`))
	if err != nil {
		t.Fatalf("send to offline node: %v", err)
	}
}

func TestOnDirectMessageHandler(t *testing.T) {
	nodes := testNodes(t, 2)
	a, b := nodes[0], nodes[1]

	// Connect a -> b.
	if _, err := a.Ping(b.Addr()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// No handler registered — should not panic.
	err := a.SendDirectMessage(b.ID(), json.RawMessage(`{"text":"no handler"}`))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	// Just verify no panic occurred.
}
