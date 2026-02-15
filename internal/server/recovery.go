package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/ssd-technologies/nocturne/internal/crypto"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

// recoverySetupRequest is the JSON body for setting up recovery.
type recoverySetupRequest struct {
	Password string `json:"password"`
}

// recoveryRecoverRequest is the JSON body for recovering a password.
type recoveryRecoverRequest struct {
	HexKey string `json:"hex_key"`
}

// handleRecoverySetup handles POST /api/recovery/setup — generate recovery keys.
func (s *Server) handleRecoverySetup(w http.ResponseWriter, r *http.Request) {
	var req recoverySetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return
	}

	// Generate recovery key + mnemonic
	hexKey, mnemonic, err := crypto.GenerateRecoveryKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate recovery key")
		return
	}

	// Create escrow blob
	salt := crypto.GenerateSalt()
	escrowBlob, err := crypto.CreateEscrow(hexKey, req.Password, salt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create escrow")
		return
	}

	// Store in DB
	rk := &storage.RecoveryKey{
		ID:         uuid.New().String(),
		HexKey:     hexKey,
		Mnemonic:   mnemonic,
		EscrowBlob: escrowBlob,
		CreatedAt:  time.Now().Unix(),
	}
	if err := s.db.CreateRecoveryKey(rk); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store recovery key")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"hex_key":  hexKey,
		"mnemonic": mnemonic,
	})
}

// handleRecoveryRecover handles POST /api/recovery/recover — recover password via hex key.
func (s *Server) handleRecoveryRecover(w http.ResponseWriter, r *http.Request) {
	var req recoveryRecoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.HexKey == "" {
		writeError(w, http.StatusBadRequest, "hex_key is required")
		return
	}

	keys, err := s.db.ListRecoveryKeys()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list recovery keys")
		return
	}

	// Try each stored recovery key's escrow
	for _, rk := range keys {
		password, _, err := crypto.RecoverFromEscrow(req.HexKey, rk.EscrowBlob)
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]string{
				"password": password,
			})
			return
		}
	}

	writeError(w, http.StatusUnauthorized, "recovery failed: invalid key")
}
