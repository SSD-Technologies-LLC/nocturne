package dht

import (
	"encoding/json"
	"fmt"
	"strings"
)

// KnowledgeEntry represents a knowledge item stored in the DHT.
type KnowledgeEntry struct {
	ID         string  `json:"id"`
	AgentID    string  `json:"agent_id"`
	OperatorID string  `json:"operator_id"`
	Type       string  `json:"type"` // "fact", "procedure", "context"
	Domain     string  `json:"domain"`
	Content    string  `json:"content"`
	Confidence float64 `json:"confidence"`
	Sources    string  `json:"sources,omitempty"`
	Supersedes string  `json:"supersedes,omitempty"`
	VotesUp    int     `json:"votes_up"`
	VotesDown  int     `json:"votes_down"`
	TTL        int64   `json:"ttl,omitempty"` // seconds, 0 = default 24h
	CreatedAt  int64   `json:"created_at"`
	Signature  string  `json:"signature"`
}

// DomainIndex stores a list of entry IDs for a domain.
type DomainIndex struct {
	Domain  string   `json:"domain"`
	Entries []string `json:"entries"`
}

// PublishKnowledge stores a knowledge entry at its content key and updates the domain index.
func (n *Node) PublishKnowledge(entry *KnowledgeEntry) error {
	// 1. Serialize the entry to JSON.
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}

	// 2. Compute content key: ContentKey(domain, id).
	key := ContentKey(entry.Domain, entry.ID)

	// 3. Store in DHT using Node.Store(key, data).
	if err := n.Store(key, data); err != nil {
		return fmt.Errorf("store entry: %w", err)
	}

	// 4. Update domain index: fetch current, append ID, re-store.
	if err := n.updateDomainIndex(entry.Domain, entry.ID, true); err != nil {
		return fmt.Errorf("update domain index: %w", err)
	}

	return nil
}

// QueryKnowledge fetches knowledge entries for a domain, optionally filtering by text and confidence.
func (n *Node) QueryKnowledge(domain string, text string, minConfidence float64, limit int) ([]KnowledgeEntry, error) {
	// 1. Fetch domain index from DHT.
	indexKey := DomainIndexKey(domain)
	data, err := n.FindValue(indexKey)
	if err != nil {
		return nil, fmt.Errorf("find domain index: %w", err)
	}
	if data == nil {
		return nil, nil // no entries for this domain
	}

	// 2. Parse domain index.
	var index DomainIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("unmarshal domain index: %w", err)
	}

	// 3. Fetch each entry by content key.
	var results []KnowledgeEntry
	for _, entryID := range index.Entries {
		entryKey := ContentKey(domain, entryID)
		entryData, err := n.FindValue(entryKey)
		if err != nil || entryData == nil {
			continue // entry may have expired
		}

		var entry KnowledgeEntry
		if err := json.Unmarshal(entryData, &entry); err != nil {
			continue
		}

		// Apply filters.
		if minConfidence > 0 && entry.Confidence < minConfidence {
			continue
		}
		if text != "" && !containsIgnoreCase(entry.Content, text) && !containsIgnoreCase(entry.Domain, text) {
			continue
		}

		results = append(results, entry)
		if limit > 0 && len(results) >= limit {
			break
		}
	}

	return results, nil
}

// DeleteKnowledge removes an entry and updates the domain index.
func (n *Node) DeleteKnowledge(entryID, domain string) error {
	// 1. Delete the content key by storing a tombstone (will expire with default TTL).
	key := ContentKey(domain, entryID)
	n.Store(key, []byte("{}")) // tombstone

	// 2. Update domain index to remove this entry.
	if err := n.updateDomainIndex(domain, entryID, false); err != nil {
		return fmt.Errorf("update domain index: %w", err)
	}

	return nil
}

// updateDomainIndex adds or removes an entry ID from the domain index.
func (n *Node) updateDomainIndex(domain, entryID string, add bool) error {
	indexKey := DomainIndexKey(domain)

	// Fetch current index.
	data, _ := n.FindValue(indexKey)

	var index DomainIndex
	if data != nil {
		json.Unmarshal(data, &index)
	}
	index.Domain = domain

	if add {
		// Deduplicate.
		found := false
		for _, id := range index.Entries {
			if id == entryID {
				found = true
				break
			}
		}
		if !found {
			index.Entries = append(index.Entries, entryID)
		}
	} else {
		// Remove.
		filtered := index.Entries[:0]
		for _, id := range index.Entries {
			if id != entryID {
				filtered = append(filtered, id)
			}
		}
		index.Entries = filtered
	}

	// Store updated index.
	indexData, err := json.Marshal(index)
	if err != nil {
		return err
	}
	return n.Store(indexKey, indexData)
}

func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
