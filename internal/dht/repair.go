package dht

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ssd-technologies/nocturne/internal/mesh"
)

// RepairResult tracks the outcome of a single repair cycle.
type RepairResult struct {
	FilesChecked   int
	ShardsChecked  int
	ShardsRepaired int
	Errors         []string
}

// RepairLoop manages periodic shard health checks and repair.
type RepairLoop struct {
	node     *Node
	interval time.Duration
	getFiles func() []string // callback to get file IDs to check
	stopCh   chan struct{}
	mu       sync.Mutex
	running  bool
}

// NewRepairLoop creates a new repair loop for the given node.
// The getFiles callback is invoked each cycle to obtain the list of file IDs
// whose shards should be checked. The interval controls how often the repair
// cycle runs (a reasonable default is 30 minutes).
func NewRepairLoop(node *Node, interval time.Duration, getFiles func() []string) *RepairLoop {
	return &RepairLoop{
		node:     node,
		interval: interval,
		getFiles: getFiles,
		stopCh:   make(chan struct{}),
	}
}

// Start begins the background repair loop. Calling Start on an already-running
// loop is a no-op.
func (rl *RepairLoop) Start() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.running {
		return
	}
	rl.running = true
	go rl.run()
}

// Stop stops the background repair loop. Calling Stop on a stopped loop is a
// no-op.
func (rl *RepairLoop) Stop() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if !rl.running {
		return
	}
	rl.running = false
	close(rl.stopCh)
}

func (rl *RepairLoop) run() {
	// Run immediately on start, then periodically.
	rl.repairCycle()

	ticker := time.NewTicker(rl.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.repairCycle()
		case <-rl.stopCh:
			return
		}
	}
}

// repairCycle runs one repair pass over all files returned by the getFiles
// callback. It checks shard availability and integrity for each file and
// reconstructs any missing or corrupted shards using Reed-Solomon.
func (rl *RepairLoop) repairCycle() RepairResult {
	result := RepairResult{}
	fileIDs := rl.getFiles()

	for _, fileID := range fileIDs {
		result.FilesChecked++
		repaired, checked, err := rl.repairFile(fileID)
		result.ShardsChecked += checked
		result.ShardsRepaired += repaired
		if err != nil {
			errMsg := fmt.Sprintf("file %s: %v", fileID, err)
			result.Errors = append(result.Errors, errMsg)
			log.Printf("repair: %s", errMsg)
		}
	}

	if result.ShardsRepaired > 0 {
		log.Printf("repair: checked %d files (%d shards), repaired %d shards, %d errors",
			result.FilesChecked, result.ShardsChecked, result.ShardsRepaired, len(result.Errors))
	}

	return result
}

// repairFile checks and repairs shards for a single file.
// Returns (shards repaired, shards checked, error).
func (rl *RepairLoop) repairFile(fileID string) (int, int, error) {
	manifest, err := rl.node.RetrieveManifest(fileID)
	if err != nil {
		return 0, 0, fmt.Errorf("retrieve manifest: %w", err)
	}

	totalShards := manifest.DataShards + manifest.ParityShards
	shards := make([][]byte, totalShards)
	var missing []int

	// Check each shard for availability and integrity.
	for i := 0; i < totalShards; i++ {
		data, err := rl.node.RetrieveShard(fileID, i)
		if err != nil {
			missing = append(missing, i)
			continue
		}
		// Verify checksum against manifest.
		if i < len(manifest.Shards) {
			checksum := sha256.Sum256(data)
			if hex.EncodeToString(checksum[:]) != manifest.Shards[i].Checksum {
				missing = append(missing, i)
				continue
			}
		}
		shards[i] = data
	}

	if len(missing) == 0 {
		return 0, totalShards, nil // all healthy
	}

	available := totalShards - len(missing)
	if available < manifest.DataShards {
		return 0, totalShards, fmt.Errorf(
			"insufficient shards for repair: have %d, need %d", available, manifest.DataShards)
	}

	// Reconstruct missing shards using Reed-Solomon.
	reconstructed, err := mesh.ReconstructShards(shards, manifest.DataShards, manifest.ParityShards)
	if err != nil {
		return 0, totalShards, fmt.Errorf("reconstruct shards: %w", err)
	}

	// Re-store each missing shard back into the DHT.
	repaired := 0
	for _, idx := range missing {
		if idx < len(reconstructed) && reconstructed[idx] != nil {
			if err := rl.node.StoreShard(fileID, idx, reconstructed[idx]); err != nil {
				log.Printf("repair: failed to re-store shard %s:%d: %v", fileID, idx, err)
				continue
			}
			repaired++
		}
	}

	return repaired, totalShards, nil
}
