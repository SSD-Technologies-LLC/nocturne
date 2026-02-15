package dht

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// voteCluster creates n DHT nodes connected in a chain for voting tests.
func voteCluster(t *testing.T, n int) []*Node {
	t.Helper()
	nodes := testNodes(t, n)
	for i := 1; i < len(nodes); i++ {
		_, err := nodes[i-1].Ping(nodes[i].Addr())
		if err != nil {
			t.Fatalf("ping node %d→%d: %v", i-1, i, err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	return nodes
}

// storeVoteRecordWithWindows creates a VoteRecord with custom commit/reveal
// windows and stores it directly in the DHT. This allows tests to use very
// short windows without modifying the production defaults.
func storeVoteRecordWithWindows(t *testing.T, n *Node, entryKey NodeID, commitEnd, revealEnd int64) {
	t.Helper()
	record := &VoteRecord{
		EntryKey:  entryKey,
		CommitEnd: commitEnd,
		RevealEnd: revealEnd,
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal vote record: %v", err)
	}
	key := PrefixKey(voteKeyPrefix, hex.EncodeToString(entryKey[:]))
	if err := n.Store(key, data); err != nil {
		t.Fatalf("store vote record: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
}

func TestSubmitCommitmentAndReveal(t *testing.T) {
	nodes := voteCluster(t, 3)
	a := nodes[0]

	entryKey := ContentKey("security", "entry-1")

	// Set up a vote record with commit window in the future.
	now := time.Now().Unix()
	commitEnd := now + 5  // 5 seconds from now
	revealEnd := now + 10 // 10 seconds from now
	storeVoteRecordWithWindows(t, a, entryKey, commitEnd, revealEnd)

	// Submit a commitment.
	nonce := "secret-nonce-123"
	vote := 1
	commitment := MakeCommitment(vote, nonce)

	if err := a.SubmitVoteCommitment(entryKey, "op-1", commitment); err != nil {
		t.Fatalf("SubmitVoteCommitment: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Verify the commitment was stored by fetching the record.
	record, err := a.getVoteRecord(entryKey)
	if err != nil {
		t.Fatalf("getVoteRecord: %v", err)
	}
	if len(record.Commitments) != 1 {
		t.Fatalf("expected 1 commitment, got %d", len(record.Commitments))
	}
	if record.Commitments[0].OperatorID != "op-1" {
		t.Fatalf("expected operator_id=op-1, got %s", record.Commitments[0].OperatorID)
	}
	if record.Commitments[0].Commitment != commitment {
		t.Fatalf("commitment mismatch")
	}

	// Now move to reveal phase: re-store the record with commit window ended.
	now2 := time.Now().Unix()
	record.CommitEnd = now2 - 1 // commit phase ended
	record.RevealEnd = now2 + 5 // reveal phase still open
	data, _ := json.Marshal(record)
	key := PrefixKey(voteKeyPrefix, hex.EncodeToString(entryKey[:]))
	if err := a.Store(key, data); err != nil {
		t.Fatalf("store updated vote record: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Submit the reveal.
	if err := a.SubmitVoteReveal(entryKey, "op-1", vote, nonce, "good entry"); err != nil {
		t.Fatalf("SubmitVoteReveal: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Verify the reveal was stored.
	record, err = a.getVoteRecord(entryKey)
	if err != nil {
		t.Fatalf("getVoteRecord after reveal: %v", err)
	}
	if len(record.Reveals) != 1 {
		t.Fatalf("expected 1 reveal, got %d", len(record.Reveals))
	}
	if record.Reveals[0].OperatorID != "op-1" {
		t.Fatalf("expected reveal operator_id=op-1, got %s", record.Reveals[0].OperatorID)
	}
	if record.Reveals[0].Vote != 1 {
		t.Fatalf("expected reveal vote=1, got %d", record.Reveals[0].Vote)
	}
	if record.Reveals[0].Reason != "good entry" {
		t.Fatalf("expected reason='good entry', got %q", record.Reveals[0].Reason)
	}
}

func TestRejectDuplicateCommitment(t *testing.T) {
	nodes := voteCluster(t, 3)
	a := nodes[0]

	entryKey := ContentKey("security", "entry-dup")

	now := time.Now().Unix()
	storeVoteRecordWithWindows(t, a, entryKey, now+5, now+10)

	commitment := MakeCommitment(1, "nonce-1")

	// First commitment should succeed.
	if err := a.SubmitVoteCommitment(entryKey, "op-1", commitment); err != nil {
		t.Fatalf("first SubmitVoteCommitment: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Second commitment from same operator should fail.
	err := a.SubmitVoteCommitment(entryKey, "op-1", commitment)
	if err == nil {
		t.Fatal("expected error on duplicate commitment")
	}
}

func TestRejectBadReveal(t *testing.T) {
	nodes := voteCluster(t, 3)
	a := nodes[0]

	entryKey := ContentKey("security", "entry-bad")

	now := time.Now().Unix()
	storeVoteRecordWithWindows(t, a, entryKey, now+5, now+10)

	// Submit commitment with one nonce.
	correctNonce := "correct-nonce"
	commitment := MakeCommitment(1, correctNonce)

	if err := a.SubmitVoteCommitment(entryKey, "op-1", commitment); err != nil {
		t.Fatalf("SubmitVoteCommitment: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Move to reveal phase.
	record, err := a.getVoteRecord(entryKey)
	if err != nil {
		t.Fatalf("getVoteRecord: %v", err)
	}
	now2 := time.Now().Unix()
	record.CommitEnd = now2 - 1
	record.RevealEnd = now2 + 5
	data, _ := json.Marshal(record)
	key := PrefixKey(voteKeyPrefix, hex.EncodeToString(entryKey[:]))
	if err := a.Store(key, data); err != nil {
		t.Fatalf("store updated vote record: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Try to reveal with wrong nonce — should fail.
	err = a.SubmitVoteReveal(entryKey, "op-1", 1, "wrong-nonce", "")
	if err == nil {
		t.Fatal("expected error on bad reveal (wrong nonce)")
	}
}

func TestTallyVotes(t *testing.T) {
	nodes := voteCluster(t, 3)
	a := nodes[0]

	entryKey := ContentKey("security", "entry-tally")

	now := time.Now().Unix()
	storeVoteRecordWithWindows(t, a, entryKey, now+5, now+10)

	// Three operators commit their votes.
	operators := []struct {
		id    string
		vote  int
		nonce string
	}{
		{"op-1", 1, "nonce-a"},
		{"op-2", 1, "nonce-b"},
		{"op-3", -1, "nonce-c"},
	}

	for _, op := range operators {
		commitment := MakeCommitment(op.vote, op.nonce)
		if err := a.SubmitVoteCommitment(entryKey, op.id, commitment); err != nil {
			t.Fatalf("SubmitVoteCommitment(%s): %v", op.id, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Move to reveal phase.
	record, err := a.getVoteRecord(entryKey)
	if err != nil {
		t.Fatalf("getVoteRecord: %v", err)
	}
	now2 := time.Now().Unix()
	record.CommitEnd = now2 - 1
	record.RevealEnd = now2 + 5
	data, _ := json.Marshal(record)
	key := PrefixKey(voteKeyPrefix, hex.EncodeToString(entryKey[:]))
	if err := a.Store(key, data); err != nil {
		t.Fatalf("store updated vote record: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// All three operators reveal.
	for _, op := range operators {
		if err := a.SubmitVoteReveal(entryKey, op.id, op.vote, op.nonce, ""); err != nil {
			t.Fatalf("SubmitVoteReveal(%s): %v", op.id, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Tally votes.
	tally, err := a.TallyVotes(entryKey)
	if err != nil {
		t.Fatalf("TallyVotes: %v", err)
	}

	if tally.UpVotes != 2 {
		t.Fatalf("expected 2 up_votes, got %d", tally.UpVotes)
	}
	if tally.DownVotes != 1 {
		t.Fatalf("expected 1 down_vote, got %d", tally.DownVotes)
	}
	if tally.Total != 3 {
		t.Fatalf("expected total=3, got %d", tally.Total)
	}
	// 2/3 = 0.666... which is less than 0.67, so Valid should be false.
	if tally.Valid {
		t.Fatal("expected Valid=false (2/3 < 0.67 threshold)")
	}

	// Verify the record is finalized.
	record, err = a.getVoteRecord(entryKey)
	if err != nil {
		t.Fatalf("getVoteRecord after tally: %v", err)
	}
	if !record.Finalized {
		t.Fatal("expected record to be finalized after tally")
	}
}

func TestTallyInsufficientVotes(t *testing.T) {
	nodes := voteCluster(t, 3)
	a := nodes[0]

	entryKey := ContentKey("security", "entry-insufficient")

	now := time.Now().Unix()
	storeVoteRecordWithWindows(t, a, entryKey, now+5, now+10)

	// Only one operator commits and reveals.
	commitment := MakeCommitment(1, "solo-nonce")
	if err := a.SubmitVoteCommitment(entryKey, "op-solo", commitment); err != nil {
		t.Fatalf("SubmitVoteCommitment: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Move to reveal phase.
	record, err := a.getVoteRecord(entryKey)
	if err != nil {
		t.Fatalf("getVoteRecord: %v", err)
	}
	now2 := time.Now().Unix()
	record.CommitEnd = now2 - 1
	record.RevealEnd = now2 + 5
	data, _ := json.Marshal(record)
	key := PrefixKey(voteKeyPrefix, hex.EncodeToString(entryKey[:]))
	if err := a.Store(key, data); err != nil {
		t.Fatalf("store updated vote record: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	if err := a.SubmitVoteReveal(entryKey, "op-solo", 1, "solo-nonce", ""); err != nil {
		t.Fatalf("SubmitVoteReveal: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Tally — should be invalid because only 1 vote (< 3 minimum).
	tally, err := a.TallyVotes(entryKey)
	if err != nil {
		t.Fatalf("TallyVotes: %v", err)
	}

	if tally.Total != 1 {
		t.Fatalf("expected total=1, got %d", tally.Total)
	}
	if tally.Valid {
		t.Fatal("expected Valid=false with insufficient votes")
	}
}

func TestRejectCommitAfterWindow(t *testing.T) {
	nodes := voteCluster(t, 3)
	a := nodes[0]

	entryKey := ContentKey("security", "entry-expired")

	// Set commit window to already be expired.
	now := time.Now().Unix()
	storeVoteRecordWithWindows(t, a, entryKey, now-2, now+5)

	commitment := MakeCommitment(1, "late-nonce")

	err := a.SubmitVoteCommitment(entryKey, "op-late", commitment)
	if err == nil {
		t.Fatal("expected error when committing after window ends")
	}
}
