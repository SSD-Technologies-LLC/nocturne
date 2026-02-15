package dht

import (
	"strings"
	"testing"
	"time"
)

// testCluster creates a 3-node DHT cluster with all nodes connected:
// A <-> B <-> C. It waits for routing tables to stabilize before returning.
func testCluster(t *testing.T) (a, b, c *Node) {
	t.Helper()
	nodes := testNodes(t, 3)
	a, b, c = nodes[0], nodes[1], nodes[2]

	// Connect A->B and B->C.
	if _, err := a.Ping(b.Addr()); err != nil {
		t.Fatalf("A ping B: %v", err)
	}
	if _, err := b.Ping(c.Addr()); err != nil {
		t.Fatalf("B ping C: %v", err)
	}

	// Wait for routing tables to stabilize.
	waitForTableSize(t, a, 1, 2*time.Second)
	waitForTableSize(t, b, 2, 2*time.Second)
	waitForTableSize(t, c, 1, 2*time.Second)

	return a, b, c
}

func TestPublishAndListTasks(t *testing.T) {
	a, b, _ := testCluster(t)

	task := &ComputeTask{
		ID:          "task-001",
		Type:        "verify",
		Domain:      "security",
		Description: "Verify the integrity of uploaded file batch #42",
		Priority:    7,
	}

	// Publish on node A.
	if err := a.PublishTask(task); err != nil {
		t.Fatalf("PublishTask: %v", err)
	}

	// Give STORE RPCs time to propagate.
	time.Sleep(300 * time.Millisecond)

	// List tasks from node B. Should find the task published by A.
	tasks, err := b.ListTasks()
	if err != nil {
		t.Fatalf("ListTasks: %v", err)
	}

	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}
	if tasks[0].ID != "task-001" {
		t.Fatalf("expected task ID task-001, got %s", tasks[0].ID)
	}
	if tasks[0].Type != "verify" {
		t.Fatalf("expected task type verify, got %s", tasks[0].Type)
	}
	if tasks[0].Domain != "security" {
		t.Fatalf("expected domain security, got %s", tasks[0].Domain)
	}
	if tasks[0].Priority != 7 {
		t.Fatalf("expected priority 7, got %d", tasks[0].Priority)
	}
	if tasks[0].CreatedAt == 0 {
		t.Fatal("expected CreatedAt to be set")
	}
}

func TestClaimTask(t *testing.T) {
	a, b, _ := testCluster(t)

	task := &ComputeTask{
		ID:          "task-claim-001",
		Type:        "summarize",
		Description: "Summarize knowledge entries in the AI domain",
		Priority:    5,
	}

	if err := a.PublishTask(task); err != nil {
		t.Fatalf("PublishTask: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// Claim the task from node B.
	claimed, err := b.ClaimTask("task-claim-001", "agent-alpha")
	if err != nil {
		t.Fatalf("ClaimTask: %v", err)
	}

	if claimed.ClaimedBy != "agent-alpha" {
		t.Fatalf("expected claimed_by=agent-alpha, got %s", claimed.ClaimedBy)
	}
	if claimed.ClaimedAt == 0 {
		t.Fatal("expected claimed_at to be set")
	}
	if claimed.Completed {
		t.Fatal("expected completed=false after claim")
	}
}

func TestClaimTaskAlreadyClaimed(t *testing.T) {
	a, b, _ := testCluster(t)

	task := &ComputeTask{
		ID:          "task-conflict-001",
		Type:        "cross_reference",
		Description: "Cross-reference entries across domains",
		Priority:    8,
	}

	if err := a.PublishTask(task); err != nil {
		t.Fatalf("PublishTask: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// Agent A claims the task.
	_, err := b.ClaimTask("task-conflict-001", "agent-alpha")
	if err != nil {
		t.Fatalf("ClaimTask (agent-alpha): %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Agent B tries to claim the same task -> should fail.
	_, err = b.ClaimTask("task-conflict-001", "agent-beta")
	if err == nil {
		t.Fatal("expected error when claiming already-claimed task")
	}
	if !strings.Contains(err.Error(), "already claimed") {
		t.Fatalf("expected 'already claimed' error, got: %v", err)
	}
}

func TestClaimTaskExpired(t *testing.T) {
	a, b, _ := testCluster(t)

	// Publish a task and manually set an old claim (simulating expired claim).
	task := &ComputeTask{
		ID:          "task-expire-001",
		Type:        "verify",
		Description: "Verify stale computation",
		Priority:    3,
		ClaimedBy:   "agent-old",
		ClaimedAt:   time.Now().Add(-2 * time.Hour).Unix(), // 2 hours ago, past claimTimeout
	}

	if err := a.PublishTask(task); err != nil {
		t.Fatalf("PublishTask: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// A new agent should be able to reclaim it since the old claim expired.
	claimed, err := b.ClaimTask("task-expire-001", "agent-new")
	if err != nil {
		t.Fatalf("ClaimTask (expired reclaim): %v", err)
	}

	if claimed.ClaimedBy != "agent-new" {
		t.Fatalf("expected claimed_by=agent-new, got %s", claimed.ClaimedBy)
	}
}

func TestSubmitTaskResult(t *testing.T) {
	a, b, _ := testCluster(t)

	task := &ComputeTask{
		ID:          "task-result-001",
		Type:        "summarize",
		Description: "Summarize mesh activity report",
		Priority:    6,
	}

	if err := a.PublishTask(task); err != nil {
		t.Fatalf("PublishTask: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// Claim the task.
	_, err := b.ClaimTask("task-result-001", "agent-worker")
	if err != nil {
		t.Fatalf("ClaimTask: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Submit a result.
	if err := b.SubmitTaskResult("task-result-001", "result-abc-123"); err != nil {
		t.Fatalf("SubmitTaskResult: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Verify the task is now completed by listing from node A.
	tasks, err := a.ListTasks()
	if err != nil {
		t.Fatalf("ListTasks: %v", err)
	}

	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}
	if !tasks[0].Completed {
		t.Fatal("expected task to be completed")
	}
	if tasks[0].ResultID != "result-abc-123" {
		t.Fatalf("expected result_id=result-abc-123, got %s", tasks[0].ResultID)
	}
}

func TestClaimTaskNotFound(t *testing.T) {
	_, b, _ := testCluster(t)

	// Try to claim a non-existent task.
	_, err := b.ClaimTask("task-nonexistent", "agent-lost")
	if err == nil {
		t.Fatal("expected error when claiming non-existent task")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got: %v", err)
	}
}
