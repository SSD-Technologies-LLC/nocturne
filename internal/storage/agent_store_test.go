package storage

import (
	"fmt"
	"testing"
	"time"
)

// --- Test helpers ---

// seedOperator creates and returns a test operator.
func seedOperator(t *testing.T, db *DB) *Operator {
	t.Helper()
	op := &Operator{
		ID:          "op-001",
		PublicKey:   []byte("operator-pub-key"),
		Label:       "Test Operator",
		ApprovedBy:  "root",
		Reputation:  1.0,
		Quarantined: false,
		MaxAgents:   5,
		CreatedAt:   time.Now().Unix(),
	}
	if err := db.CreateOperator(op); err != nil {
		t.Fatalf("seedOperator: %v", err)
	}
	return op
}

// --- Task 3: Operator CRUD tests ---

func TestCreateAndGetOperator(t *testing.T) {
	db := testDB(t)
	op := seedOperator(t, db)

	got, err := db.GetOperator(op.ID)
	if err != nil {
		t.Fatalf("GetOperator: %v", err)
	}
	if got.ID != op.ID {
		t.Errorf("ID = %q, want %q", got.ID, op.ID)
	}
	if string(got.PublicKey) != string(op.PublicKey) {
		t.Errorf("PublicKey mismatch")
	}
	if got.Label != op.Label {
		t.Errorf("Label = %q, want %q", got.Label, op.Label)
	}
	if got.ApprovedBy != op.ApprovedBy {
		t.Errorf("ApprovedBy = %q, want %q", got.ApprovedBy, op.ApprovedBy)
	}
	if got.Reputation != op.Reputation {
		t.Errorf("Reputation = %f, want %f", got.Reputation, op.Reputation)
	}
	if got.Quarantined != false {
		t.Errorf("Quarantined = %v, want false", got.Quarantined)
	}
	if got.MaxAgents != op.MaxAgents {
		t.Errorf("MaxAgents = %d, want %d", got.MaxAgents, op.MaxAgents)
	}
}

func TestGetOperatorByPublicKey(t *testing.T) {
	db := testDB(t)
	op := seedOperator(t, db)

	got, err := db.GetOperatorByPublicKey(op.PublicKey)
	if err != nil {
		t.Fatalf("GetOperatorByPublicKey: %v", err)
	}
	if got.ID != op.ID {
		t.Errorf("ID = %q, want %q", got.ID, op.ID)
	}
}

func TestListOperators(t *testing.T) {
	db := testDB(t)
	for i := 0; i < 3; i++ {
		op := &Operator{
			ID:         fmt.Sprintf("op-%03d", i),
			PublicKey:  []byte(fmt.Sprintf("pubkey-%d", i)),
			Label:      fmt.Sprintf("Operator %d", i),
			ApprovedBy: "root",
			MaxAgents:  5,
			CreatedAt:  time.Now().Unix(),
		}
		if err := db.CreateOperator(op); err != nil {
			t.Fatalf("CreateOperator[%d]: %v", i, err)
		}
	}

	ops, err := db.ListOperators()
	if err != nil {
		t.Fatalf("ListOperators: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("len = %d, want 3", len(ops))
	}
}

func TestQuarantineOperator(t *testing.T) {
	db := testDB(t)
	op := seedOperator(t, db)

	// Quarantine.
	if err := db.QuarantineOperator(op.ID, true); err != nil {
		t.Fatalf("QuarantineOperator(true): %v", err)
	}
	got, err := db.GetOperator(op.ID)
	if err != nil {
		t.Fatalf("GetOperator: %v", err)
	}
	if !got.Quarantined {
		t.Error("Quarantined = false after quarantine, want true")
	}

	// Un-quarantine.
	if err := db.QuarantineOperator(op.ID, false); err != nil {
		t.Fatalf("QuarantineOperator(false): %v", err)
	}
	got, err = db.GetOperator(op.ID)
	if err != nil {
		t.Fatalf("GetOperator: %v", err)
	}
	if got.Quarantined {
		t.Error("Quarantined = true after un-quarantine, want false")
	}
}

func TestUpdateOperatorReputation(t *testing.T) {
	db := testDB(t)
	op := seedOperator(t, db)

	if err := db.UpdateOperatorReputation(op.ID, 3.75); err != nil {
		t.Fatalf("UpdateOperatorReputation: %v", err)
	}
	got, err := db.GetOperator(op.ID)
	if err != nil {
		t.Fatalf("GetOperator: %v", err)
	}
	if got.Reputation != 3.75 {
		t.Errorf("Reputation = %f, want 3.75", got.Reputation)
	}
}

func TestDeleteOperator(t *testing.T) {
	db := testDB(t)
	op := seedOperator(t, db)

	if err := db.DeleteOperator(op.ID); err != nil {
		t.Fatalf("DeleteOperator: %v", err)
	}

	// Operator should be gone.
	_, err := db.GetOperator(op.ID)
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}
