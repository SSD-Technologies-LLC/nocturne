package dht

import (
	"encoding/json"
	"fmt"
	"time"
)

// ComputeTask represents a computation task distributed via the DHT.
type ComputeTask struct {
	ID          string `json:"id"`
	Type        string `json:"type"` // "verify", "summarize", "cross_reference"
	Domain      string `json:"domain,omitempty"`
	Description string `json:"description"`
	Priority    int    `json:"priority"` // 1-10, higher = more important
	ClaimedBy   string `json:"claimed_by,omitempty"`
	ClaimedAt   int64  `json:"claimed_at,omitempty"`
	Completed   bool   `json:"completed"`
	ResultID    string `json:"result_id,omitempty"`
	CreatedAt   int64  `json:"created_at"`
}

// TaskIndex stores a list of task IDs (analogous to DomainIndex).
type TaskIndex struct {
	Tasks []string `json:"tasks"`
}

const (
	taskKeyPrefix = "task"
	taskIndexKey  = "task_index"
	claimTimeout  = 1 * time.Hour
)

// PublishTask stores a compute task in the DHT and updates the task index.
func (n *Node) PublishTask(task *ComputeTask) error {
	if task.CreatedAt == 0 {
		task.CreatedAt = time.Now().Unix()
	}

	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("marshal task: %w", err)
	}

	// Store task at its key.
	key := PrefixKey(taskKeyPrefix, task.ID)
	if err := n.Store(key, data); err != nil {
		return fmt.Errorf("store task: %w", err)
	}

	// Update task index.
	return n.updateTaskIndex(task.ID, true)
}

// maxCASRetries is the maximum number of compare-and-swap retry attempts.
const maxCASRetries = 3

// ClaimTask attempts to claim a task for an agent. Returns the task if
// successfully claimed. Uses compare-and-swap for optimistic concurrency:
// if the version changes between read and write (concurrent claim), retries
// up to maxCASRetries times. If already claimed by another agent (and not
// expired), returns an error.
func (n *Node) ClaimTask(taskID, agentID string) (*ComputeTask, error) {
	key := PrefixKey(taskKeyPrefix, taskID)

	for attempt := 0; attempt < maxCASRetries; attempt++ {
		// 1. Try versioned local read first.
		data, version, err := n.FindValueVersioned(key)
		if err != nil {
			return nil, fmt.Errorf("find task: %w", err)
		}

		// If not found locally, fall back to network lookup, then store locally.
		if data == nil {
			netData, netErr := n.FindValue(key)
			if netErr != nil {
				return nil, fmt.Errorf("find task (network): %w", netErr)
			}
			if netData == nil {
				return nil, fmt.Errorf("task %s not found", taskID)
			}
			version, err = n.StoreLocal(key, netData)
			if err != nil {
				return nil, fmt.Errorf("store local: %w", err)
			}
			data = netData
		}

		var task ComputeTask
		if err := json.Unmarshal(data, &task); err != nil {
			return nil, fmt.Errorf("unmarshal task: %w", err)
		}

		// 2. Check if already claimed (and not expired).
		if task.ClaimedBy != "" && !task.Completed {
			claimAge := time.Since(time.Unix(task.ClaimedAt, 0))
			if claimAge < claimTimeout {
				return nil, fmt.Errorf("task %s already claimed by %s", taskID, task.ClaimedBy)
			}
			// Claim expired, allow re-claim.
		}

		// 3. Claim it.
		task.ClaimedBy = agentID
		task.ClaimedAt = time.Now().Unix()

		// 4. CAS the updated task.
		updatedData, err := json.Marshal(task)
		if err != nil {
			return nil, err
		}
		_, casErr := n.CompareAndSwapLocal(key, updatedData, version)
		if casErr == ErrVersionConflict {
			continue // retry
		}
		if casErr != nil {
			return nil, fmt.Errorf("cas claim task: %w", casErr)
		}

		// 5. Best-effort async replication to network.
		n.replicateToNetwork(key, updatedData)

		return &task, nil
	}

	return nil, fmt.Errorf("task %s: claim failed after %d retries (version conflict)", taskID, maxCASRetries)
}

// SubmitTaskResult marks a task as completed with a result. Uses CAS to
// prevent concurrent modifications from overwriting each other.
func (n *Node) SubmitTaskResult(taskID, resultID string) error {
	key := PrefixKey(taskKeyPrefix, taskID)

	for attempt := 0; attempt < maxCASRetries; attempt++ {
		data, version, err := n.FindValueVersioned(key)
		if err != nil {
			return fmt.Errorf("find task: %w", err)
		}
		if data == nil {
			netData, netErr := n.FindValue(key)
			if netErr != nil {
				return fmt.Errorf("find task (network): %w", netErr)
			}
			if netData == nil {
				return fmt.Errorf("task %s not found", taskID)
			}
			version, err = n.StoreLocal(key, netData)
			if err != nil {
				return fmt.Errorf("store local: %w", err)
			}
			data = netData
		}

		var task ComputeTask
		if err := json.Unmarshal(data, &task); err != nil {
			return fmt.Errorf("unmarshal task: %w", err)
		}

		task.Completed = true
		task.ResultID = resultID

		updatedData, err := json.Marshal(task)
		if err != nil {
			return err
		}
		_, casErr := n.CompareAndSwapLocal(key, updatedData, version)
		if casErr == ErrVersionConflict {
			continue
		}
		if casErr != nil {
			return fmt.Errorf("cas submit result: %w", casErr)
		}

		n.replicateToNetwork(key, updatedData)
		return nil
	}

	return fmt.Errorf("task %s: submit result failed after %d retries (version conflict)", taskID, maxCASRetries)
}

// ListTasks returns all known tasks from the task index.
func (n *Node) ListTasks() ([]ComputeTask, error) {
	indexKey := PrefixKey(taskIndexKey, "all")
	data, err := n.FindValue(indexKey)
	if err != nil {
		return nil, fmt.Errorf("find task index: %w", err)
	}
	if data == nil {
		return nil, nil
	}

	var index TaskIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, err
	}

	var tasks []ComputeTask
	for _, id := range index.Tasks {
		key := PrefixKey(taskKeyPrefix, id)
		taskData, err := n.FindValue(key)
		if err != nil || taskData == nil {
			continue
		}
		var task ComputeTask
		if err := json.Unmarshal(taskData, &task); err != nil {
			continue
		}
		tasks = append(tasks, task)
	}
	return tasks, nil
}

func (n *Node) updateTaskIndex(taskID string, add bool) error {
	indexKey := PrefixKey(taskIndexKey, "all")

	for attempt := 0; attempt < maxCASRetries; attempt++ {
		data, version, err := n.FindValueVersioned(indexKey)
		if err != nil {
			return fmt.Errorf("find task index: %w", err)
		}

		// If not found locally, try network.
		if data == nil {
			netData, _ := n.FindValue(indexKey)
			if netData != nil {
				version, err = n.StoreLocal(indexKey, netData)
				if err != nil {
					return fmt.Errorf("store local index: %w", err)
				}
				data = netData
			}
		}

		var index TaskIndex
		if data != nil {
			json.Unmarshal(data, &index)
		}

		if add {
			// Deduplicate.
			for _, id := range index.Tasks {
				if id == taskID {
					return nil // already in index
				}
			}
			index.Tasks = append(index.Tasks, taskID)
		} else {
			filtered := index.Tasks[:0]
			for _, id := range index.Tasks {
				if id != taskID {
					filtered = append(filtered, id)
				}
			}
			index.Tasks = filtered
		}

		indexData, err := json.Marshal(index)
		if err != nil {
			return err
		}

		// For new entries (version 0), use StoreLocal; otherwise CAS.
		if version == 0 {
			_, storeErr := n.StoreLocal(indexKey, indexData)
			if storeErr != nil {
				return fmt.Errorf("store task index: %w", storeErr)
			}
			n.replicateToNetwork(indexKey, indexData)
			return nil
		}

		_, casErr := n.CompareAndSwapLocal(indexKey, indexData, version)
		if casErr == ErrVersionConflict {
			continue
		}
		if casErr != nil {
			return fmt.Errorf("cas task index: %w", casErr)
		}

		n.replicateToNetwork(indexKey, indexData)
		return nil
	}

	return fmt.Errorf("update task index: failed after %d retries (version conflict)", maxCASRetries)
}
