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

// --- Agent Key CRUD ---

// CreateAgentKey inserts a new agent key, enforcing the operator's max_agents limit.
func (d *DB) CreateAgentKey(ak *AgentKey) error {
	// Check operator's max_agents limit.
	var maxAgents int
	err := d.db.QueryRow(
		`SELECT max_agents FROM operators WHERE id = ?`, ak.OperatorID,
	).Scan(&maxAgents)
	if err != nil {
		return fmt.Errorf("create agent key: lookup operator: %w", err)
	}

	var count int
	err = d.db.QueryRow(
		`SELECT COUNT(*) FROM agent_keys WHERE operator_id = ?`, ak.OperatorID,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("create agent key: count agents: %w", err)
	}
	if count >= maxAgents {
		return fmt.Errorf("create agent key: operator %s has reached max agents limit (%d)", ak.OperatorID, maxAgents)
	}

	_, err = d.db.Exec(
		`INSERT INTO agent_keys (id, operator_id, public_key, label, last_seen, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		ak.ID, ak.OperatorID, ak.PublicKey, ak.Label, ak.LastSeen, ak.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create agent key: %w", err)
	}
	return nil
}

// GetAgentKey retrieves an agent key by ID.
func (d *DB) GetAgentKey(id string) (*AgentKey, error) {
	ak := &AgentKey{}
	err := d.db.QueryRow(
		`SELECT id, operator_id, public_key, label, last_seen, created_at
		 FROM agent_keys WHERE id = ?`, id,
	).Scan(&ak.ID, &ak.OperatorID, &ak.PublicKey, &ak.Label, &ak.LastSeen, &ak.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get agent key: %w", err)
	}
	return ak, nil
}

// GetAgentKeyByPublicKey retrieves an agent key by its public key.
func (d *DB) GetAgentKeyByPublicKey(pubKey []byte) (*AgentKey, error) {
	ak := &AgentKey{}
	err := d.db.QueryRow(
		`SELECT id, operator_id, public_key, label, last_seen, created_at
		 FROM agent_keys WHERE public_key = ?`, pubKey,
	).Scan(&ak.ID, &ak.OperatorID, &ak.PublicKey, &ak.Label, &ak.LastSeen, &ak.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get agent key by public key: %w", err)
	}
	return ak, nil
}

// ListAgentKeysForOperator returns all agent keys belonging to an operator.
func (d *DB) ListAgentKeysForOperator(operatorID string) ([]AgentKey, error) {
	rows, err := d.db.Query(
		`SELECT id, operator_id, public_key, label, last_seen, created_at
		 FROM agent_keys WHERE operator_id = ?`, operatorID,
	)
	if err != nil {
		return nil, fmt.Errorf("list agent keys: %w", err)
	}
	defer rows.Close()

	var keys []AgentKey
	for rows.Next() {
		var ak AgentKey
		if err := rows.Scan(&ak.ID, &ak.OperatorID, &ak.PublicKey, &ak.Label,
			&ak.LastSeen, &ak.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan agent key: %w", err)
		}
		keys = append(keys, ak)
	}
	return keys, rows.Err()
}

// UpdateAgentLastSeen updates the last_seen timestamp for an agent key.
func (d *DB) UpdateAgentLastSeen(id string, lastSeen int64) error {
	res, err := d.db.Exec(
		`UPDATE agent_keys SET last_seen = ? WHERE id = ?`,
		lastSeen, id,
	)
	if err != nil {
		return fmt.Errorf("update agent last seen: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update agent last seen rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("update agent last seen: %w", sql.ErrNoRows)
	}
	return nil
}

// DeleteAgentKey removes an agent key by ID.
func (d *DB) DeleteAgentKey(id string) error {
	res, err := d.db.Exec(`DELETE FROM agent_keys WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete agent key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete agent key rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("delete agent key: %w", sql.ErrNoRows)
	}
	return nil
}
