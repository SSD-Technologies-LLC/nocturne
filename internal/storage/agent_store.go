package storage

import (
	"database/sql"
	"fmt"
)

// --- Operator CRUD ---

// CreateOperator inserts a new operator record.
func (d *DB) CreateOperator(op *Operator) error {
	_, err := d.db.Exec(
		`INSERT INTO operators (id, public_key, label, approved_by, reputation, quarantined, max_agents, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		op.ID, op.PublicKey, op.Label, op.ApprovedBy, op.Reputation,
		boolToInt(op.Quarantined), op.MaxAgents, op.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create operator: %w", err)
	}
	return nil
}

// GetOperator retrieves an operator by ID.
func (d *DB) GetOperator(id string) (*Operator, error) {
	op := &Operator{}
	var quarantined int
	err := d.db.QueryRow(
		`SELECT id, public_key, label, approved_by, reputation, quarantined, max_agents, created_at
		 FROM operators WHERE id = ?`, id,
	).Scan(&op.ID, &op.PublicKey, &op.Label, &op.ApprovedBy, &op.Reputation,
		&quarantined, &op.MaxAgents, &op.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get operator: %w", err)
	}
	op.Quarantined = quarantined == 1
	return op, nil
}

// GetOperatorByPublicKey retrieves an operator by its public key.
func (d *DB) GetOperatorByPublicKey(pubKey []byte) (*Operator, error) {
	op := &Operator{}
	var quarantined int
	err := d.db.QueryRow(
		`SELECT id, public_key, label, approved_by, reputation, quarantined, max_agents, created_at
		 FROM operators WHERE public_key = ?`, pubKey,
	).Scan(&op.ID, &op.PublicKey, &op.Label, &op.ApprovedBy, &op.Reputation,
		&quarantined, &op.MaxAgents, &op.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get operator by public key: %w", err)
	}
	op.Quarantined = quarantined == 1
	return op, nil
}

// ListOperators returns all operators.
func (d *DB) ListOperators() ([]Operator, error) {
	rows, err := d.db.Query(
		`SELECT id, public_key, label, approved_by, reputation, quarantined, max_agents, created_at
		 FROM operators`,
	)
	if err != nil {
		return nil, fmt.Errorf("list operators: %w", err)
	}
	defer rows.Close()

	var ops []Operator
	for rows.Next() {
		var op Operator
		var quarantined int
		if err := rows.Scan(&op.ID, &op.PublicKey, &op.Label, &op.ApprovedBy,
			&op.Reputation, &quarantined, &op.MaxAgents, &op.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan operator: %w", err)
		}
		op.Quarantined = quarantined == 1
		ops = append(ops, op)
	}
	return ops, rows.Err()
}

// QuarantineOperator sets the quarantined flag for an operator.
func (d *DB) QuarantineOperator(id string, quarantine bool) error {
	res, err := d.db.Exec(
		`UPDATE operators SET quarantined = ? WHERE id = ?`,
		boolToInt(quarantine), id,
	)
	if err != nil {
		return fmt.Errorf("quarantine operator: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("quarantine operator rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("quarantine operator: %w", sql.ErrNoRows)
	}
	return nil
}

// UpdateOperatorReputation sets the reputation score for an operator.
func (d *DB) UpdateOperatorReputation(id string, reputation float64) error {
	res, err := d.db.Exec(
		`UPDATE operators SET reputation = ? WHERE id = ?`,
		reputation, id,
	)
	if err != nil {
		return fmt.Errorf("update operator reputation: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update operator reputation rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("update operator reputation: %w", sql.ErrNoRows)
	}
	return nil
}

// DeleteOperator removes an operator and cascades to delete its agent keys.
func (d *DB) DeleteOperator(id string) error {
	// Delete agent keys first (cascade).
	if _, err := d.db.Exec(`DELETE FROM agent_keys WHERE operator_id = ?`, id); err != nil {
		return fmt.Errorf("delete operator agent keys: %w", err)
	}
	res, err := d.db.Exec(`DELETE FROM operators WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete operator: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete operator rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("delete operator: %w", sql.ErrNoRows)
	}
	return nil
}
