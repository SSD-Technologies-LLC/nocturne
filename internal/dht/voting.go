package dht

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	voteKeyPrefix       = "vote"
	defaultCommitWindow = 24 * time.Hour
	defaultRevealWindow = 12 * time.Hour
	bftThreshold        = 0.67
)

// VoteCommitment stores a single operator's vote commitment.
type VoteCommitment struct {
	OperatorID  string `json:"operator_id"`
	Commitment  string `json:"commitment"` // hex(SHA-256(vote_value + nonce))
	CommittedAt int64  `json:"committed_at"`
}

// VoteReveal stores a revealed vote.
type VoteReveal struct {
	OperatorID string `json:"operator_id"`
	Vote       int    `json:"vote"` // +1 (upvote) or -1 (downvote)
	Nonce      string `json:"nonce"`
	Reason     string `json:"reason,omitempty"`
	RevealedAt int64  `json:"revealed_at"`
}

// VoteRecord aggregates all commitments and reveals for one DHT entry.
type VoteRecord struct {
	EntryKey    NodeID           `json:"entry_key"`
	Commitments []VoteCommitment `json:"commitments"`
	Reveals     []VoteReveal     `json:"reveals"`
	CommitEnd   int64            `json:"commit_end"` // unix timestamp
	RevealEnd   int64            `json:"reveal_end"` // unix timestamp
	Finalized   bool             `json:"finalized"`
}

// VoteTally is the result of tallying votes.
type VoteTally struct {
	EntryKey  NodeID `json:"entry_key"`
	UpVotes   int    `json:"up_votes"`
	DownVotes int    `json:"down_votes"`
	Total     int    `json:"total"`
	Valid     bool   `json:"valid"` // true if enough votes for BFT threshold
}

// MakeCommitment returns hex(SHA-256(fmt.Sprintf("%d%s", vote, nonce))).
func MakeCommitment(vote int, nonce string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d%s", vote, nonce)))
	return hex.EncodeToString(h[:])
}

// voteRecordKey returns the DHT key for a vote record.
func voteRecordKey(entryKey NodeID) NodeID {
	return PrefixKey(voteKeyPrefix, hex.EncodeToString(entryKey[:]))
}

// getVoteRecord fetches a VoteRecord from the DHT, or returns nil if not found.
func (n *Node) getVoteRecord(entryKey NodeID) (*VoteRecord, error) {
	key := voteRecordKey(entryKey)
	data, err := n.FindValue(key)
	if err != nil {
		return nil, fmt.Errorf("find vote record: %w", err)
	}
	if data == nil {
		return nil, nil
	}
	var record VoteRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("unmarshal vote record: %w", err)
	}
	return &record, nil
}

// storeVoteRecord stores a VoteRecord in the DHT.
func (n *Node) storeVoteRecord(record *VoteRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal vote record: %w", err)
	}
	key := voteRecordKey(record.EntryKey)
	return n.Store(key, data)
}

// SubmitVoteCommitment submits a vote commitment for the given entry. If no
// VoteRecord exists yet, a new one is created with default commit/reveal windows.
// Rejects if the commit window has passed or if the operator already committed.
func (n *Node) SubmitVoteCommitment(entryKey NodeID, operatorID, commitment string) error {
	record, err := n.getVoteRecord(entryKey)
	if err != nil {
		return err
	}

	now := time.Now().Unix()

	if record == nil {
		// Create a new vote record with default windows.
		record = &VoteRecord{
			EntryKey:  entryKey,
			CommitEnd: now + int64(defaultCommitWindow.Seconds()),
			RevealEnd: now + int64((defaultCommitWindow + defaultRevealWindow).Seconds()),
		}
	}

	// Reject if commit window has passed.
	if now > record.CommitEnd {
		return fmt.Errorf("commit window has ended")
	}

	// Reject duplicate commitment from same operator.
	for _, c := range record.Commitments {
		if c.OperatorID == operatorID {
			return fmt.Errorf("operator %s already committed", operatorID)
		}
	}

	// Append commitment.
	record.Commitments = append(record.Commitments, VoteCommitment{
		OperatorID:  operatorID,
		Commitment:  commitment,
		CommittedAt: now,
	})

	return n.storeVoteRecord(record)
}

// SubmitVoteReveal reveals a vote for the given entry. Verifies that the
// reveal matches a previously submitted commitment using SHA-256.
func (n *Node) SubmitVoteReveal(entryKey NodeID, operatorID string, vote int, nonce, reason string) error {
	record, err := n.getVoteRecord(entryKey)
	if err != nil {
		return err
	}
	if record == nil {
		return fmt.Errorf("no vote record found for entry")
	}

	now := time.Now().Unix()

	// Reject if reveal window hasn't started (still in commit phase).
	if now < record.CommitEnd {
		return fmt.Errorf("reveal window has not started yet")
	}

	// Reject if reveal window has ended.
	if now > record.RevealEnd {
		return fmt.Errorf("reveal window has ended")
	}

	// Find matching commitment.
	expectedCommitment := MakeCommitment(vote, nonce)
	found := false
	for _, c := range record.Commitments {
		if c.OperatorID == operatorID {
			if c.Commitment != expectedCommitment {
				return fmt.Errorf("commitment mismatch for operator %s", operatorID)
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("no commitment found for operator %s", operatorID)
	}

	// Reject duplicate reveals from same operator.
	for _, r := range record.Reveals {
		if r.OperatorID == operatorID {
			return fmt.Errorf("operator %s already revealed", operatorID)
		}
	}

	// Append reveal.
	record.Reveals = append(record.Reveals, VoteReveal{
		OperatorID: operatorID,
		Vote:       vote,
		Nonce:      nonce,
		Reason:     reason,
		RevealedAt: now,
	})

	return n.storeVoteRecord(record)
}

// TallyVotes tallies the revealed votes for the given entry. Only revealed
// votes count. Valid is true when total >= 3 and the majority exceeds the
// BFT threshold (67%).
func (n *Node) TallyVotes(entryKey NodeID) (*VoteTally, error) {
	record, err := n.getVoteRecord(entryKey)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("no vote record found for entry")
	}

	tally := &VoteTally{EntryKey: entryKey}

	for _, r := range record.Reveals {
		if r.Vote > 0 {
			tally.UpVotes++
		} else {
			tally.DownVotes++
		}
	}
	tally.Total = tally.UpVotes + tally.DownVotes

	// Valid if total >= 3 and the majority exceeds BFT threshold.
	if tally.Total >= 3 {
		majority := tally.UpVotes
		if tally.DownVotes > majority {
			majority = tally.DownVotes
		}
		if float64(majority)/float64(tally.Total) >= bftThreshold {
			tally.Valid = true
		}
	}

	// Mark record as finalized.
	record.Finalized = true
	if err := n.storeVoteRecord(record); err != nil {
		return nil, fmt.Errorf("finalize vote record: %w", err)
	}

	return tally, nil
}
