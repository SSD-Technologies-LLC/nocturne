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

// ClaimTask attempts to claim a task for an agent. Returns the task if
// successfully claimed. Uses first-writer-wins: if already claimed by another
// agent (and not expired), returns an error.
func (n *Node) ClaimTask(taskID, agentID string) (*ComputeTask, error) {
	// 1. Fetch the task.
	key := PrefixKey(taskKeyPrefix, taskID)
	data, err := n.FindValue(key)
	if err != nil {
		return nil, fmt.Errorf("find task: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("task %s not found", taskID)
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

	// 4. Store updated task.
	updatedData, err := json.Marshal(task)
	if err != nil {
		return nil, err
	}
	if err := n.Store(key, updatedData); err != nil {
		return nil, fmt.Errorf("store claimed task: %w", err)
	}

	return &task, nil
}

// SubmitTaskResult marks a task as completed with a result.
func (n *Node) SubmitTaskResult(taskID, resultID string) error {
	key := PrefixKey(taskKeyPrefix, taskID)
	data, err := n.FindValue(key)
	if err != nil {
		return fmt.Errorf("find task: %w", err)
	}
	if data == nil {
		return fmt.Errorf("task %s not found", taskID)
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
	return n.Store(key, updatedData)
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

	data, _ := n.FindValue(indexKey)

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
	return n.Store(indexKey, indexData)
}
