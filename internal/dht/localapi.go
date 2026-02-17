package dht

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// LocalAPI exposes a DHT Node's functionality as a localhost HTTP REST API.
// All endpoints are prefixed with /local/ and return JSON responses.
type LocalAPI struct {
	node *Node
}

// NewLocalAPI creates a new LocalAPI wrapping the given DHT node.
func NewLocalAPI(node *Node) *LocalAPI {
	return &LocalAPI{node: node}
}

// Handler returns an http.Handler that routes requests to the appropriate
// LocalAPI methods. Designed to be mounted on a localhost-only HTTP server.
func (api *LocalAPI) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/local/health", api.handleHealth)
	mux.HandleFunc("/local/peers", api.handlePeers)
	mux.HandleFunc("/local/knowledge/vote", api.handleKnowledgeVote)
	mux.HandleFunc("/local/knowledge/tally", api.handleKnowledgeTally)
	mux.HandleFunc("/local/knowledge", api.handleKnowledge)
	mux.HandleFunc("/local/knowledge/", api.handleKnowledgeByID)
	mux.HandleFunc("/local/compute/claim", api.handleComputeClaim)
	mux.HandleFunc("/local/compute/", api.handleComputeByID)
	mux.HandleFunc("/local/compute", api.handleCompute)
	mux.HandleFunc("/local/awareness", api.handleAwareness)
	mux.HandleFunc("/local/files/", api.handleFilesByID)
	mux.HandleFunc("/local/files", api.handleFiles)
	mux.HandleFunc("/local/messages/send", api.handleMessageSend)
	mux.HandleFunc("/local/messages/inbox/", api.handleMessageInboxByNonce)
	mux.HandleFunc("/local/messages/inbox", api.handleMessageInbox)

	return mux
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// maxAPIBodySize is the maximum allowed request body for LocalAPI endpoints.
const maxAPIBodySize = 10 << 20 // 10 MB

// readBody reads and returns the request body, enforcing a size limit.
// Returns nil, false if the body exceeds the limit or cannot be read.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAPIBodySize+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return nil, false
	}
	if len(body) > maxAPIBodySize {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return nil, false
	}
	return body, true
}

// handleHealth responds with node health status.
// GET /local/health
func (api *LocalAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := api.node.ID()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"node_id": hex.EncodeToString(id[:]),
		"peers":   api.node.Table().Size(),
	})
}

// handlePeers lists all known peers in the routing table.
// GET /local/peers
func (api *LocalAPI) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Retrieve all peers by querying for the node's own ID with a large limit.
	allPeers := api.node.Table().ClosestN(api.node.ID(), 1000)

	type peerEntry struct {
		ID      string `json:"id"`
		Address string `json:"address"`
	}

	peers := make([]peerEntry, 0, len(allPeers))
	for _, p := range allPeers {
		peers = append(peers, peerEntry{
			ID:      hex.EncodeToString(p.ID[:]),
			Address: p.Address,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"peers": peers,
	})
}

// handleKnowledge handles knowledge publishing and querying.
// POST /local/knowledge       -> PublishKnowledge
// GET  /local/knowledge?...   -> QueryKnowledge
func (api *LocalAPI) handleKnowledge(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		api.publishKnowledge(w, r)
	case http.MethodGet:
		api.queryKnowledge(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (api *LocalAPI) publishKnowledge(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var entry KnowledgeEntry
	if err := json.Unmarshal(body, &entry); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if err := api.node.PublishKnowledge(&entry); err != nil {
		writeError(w, http.StatusInternalServerError, "publish failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "published", "id": entry.ID})
}

func (api *LocalAPI) queryKnowledge(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain parameter required")
		return
	}

	text := r.URL.Query().Get("text")
	minConfidence := 0.0
	if mc := r.URL.Query().Get("min_confidence"); mc != "" {
		if v, err := strconv.ParseFloat(mc, 64); err == nil {
			minConfidence = v
		}
	}
	limit := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil {
			limit = v
		}
	}

	results, err := api.node.QueryKnowledge(domain, text, minConfidence, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed: "+err.Error())
		return
	}

	if results == nil {
		results = []KnowledgeEntry{}
	}
	writeJSON(w, http.StatusOK, results)
}

// handleKnowledgeByID handles DELETE /local/knowledge/{id}?domain=D
func (api *LocalAPI) handleKnowledgeByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Parse entry ID from URL path: /local/knowledge/{id}
	path := strings.TrimPrefix(r.URL.Path, "/local/knowledge/")
	entryID := path
	if entryID == "" {
		writeError(w, http.StatusBadRequest, "entry ID required in path")
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain parameter required")
		return
	}

	if err := api.node.DeleteKnowledge(entryID, domain); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": entryID})
}

// handleKnowledgeVote handles vote commitment and reveal.
// POST /local/knowledge/vote
//
// Body for commitment: {"entry_key":"hex","operator_id":"...","phase":"commit","commitment":"hex"}
// Body for reveal:     {"entry_key":"hex","operator_id":"...","phase":"reveal","vote":1,"nonce":"...","reason":"..."}
func (api *LocalAPI) handleKnowledgeVote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req struct {
		EntryKey   string `json:"entry_key"`
		OperatorID string `json:"operator_id"`
		Phase      string `json:"phase"`
		Commitment string `json:"commitment,omitempty"`
		Vote       *int   `json:"vote,omitempty"`
		Nonce      string `json:"nonce,omitempty"`
		Reason     string `json:"reason,omitempty"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Parse entry key from hex.
	keyBytes, err := hex.DecodeString(req.EntryKey)
	if err != nil || len(keyBytes) != IDLength {
		writeError(w, http.StatusBadRequest, "invalid entry_key: must be 64-char hex")
		return
	}
	var entryKey NodeID
	copy(entryKey[:], keyBytes)

	switch req.Phase {
	case "commit":
		if req.Commitment == "" {
			writeError(w, http.StatusBadRequest, "commitment required for commit phase")
			return
		}
		if err := api.node.SubmitVoteCommitment(entryKey, req.OperatorID, req.Commitment); err != nil {
			writeError(w, http.StatusInternalServerError, "commit failed: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "committed"})

	case "reveal":
		if req.Vote == nil {
			writeError(w, http.StatusBadRequest, "vote required for reveal phase")
			return
		}
		if err := api.node.SubmitVoteReveal(entryKey, req.OperatorID, *req.Vote, req.Nonce, req.Reason); err != nil {
			writeError(w, http.StatusInternalServerError, "reveal failed: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revealed"})

	default:
		writeError(w, http.StatusBadRequest, "phase must be 'commit' or 'reveal'")
	}
}

// handleKnowledgeTally handles vote tallying.
// GET /local/knowledge/tally?key=hex
func (api *LocalAPI) handleKnowledgeTally(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	keyHex := r.URL.Query().Get("key")
	if keyHex == "" {
		writeError(w, http.StatusBadRequest, "key parameter required")
		return
	}

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil || len(keyBytes) != IDLength {
		writeError(w, http.StatusBadRequest, "invalid key: must be 64-char hex")
		return
	}
	var entryKey NodeID
	copy(entryKey[:], keyBytes)

	tally, err := api.node.TallyVotes(entryKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "tally failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, tally)
}

// handleCompute handles task listing.
// GET /local/compute
func (api *LocalAPI) handleCompute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	tasks, err := api.node.ListTasks()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list tasks failed: "+err.Error())
		return
	}

	if tasks == nil {
		tasks = []ComputeTask{}
	}
	writeJSON(w, http.StatusOK, tasks)
}

// handleComputeClaim handles task claiming.
// POST /local/compute/claim  body: {"task_id":"...","agent_id":"..."}
func (api *LocalAPI) handleComputeClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req struct {
		TaskID  string `json:"task_id"`
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.TaskID == "" || req.AgentID == "" {
		writeError(w, http.StatusBadRequest, "task_id and agent_id required")
		return
	}

	claimed, err := api.node.ClaimTask(req.TaskID, req.AgentID)
	if err != nil {
		writeError(w, http.StatusConflict, "claim failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, claimed)
}

// handleComputeByID handles task result submission.
// POST /local/compute/{id}/result  body: {"result_id":"..."}
func (api *LocalAPI) handleComputeByID(w http.ResponseWriter, r *http.Request) {
	// Parse: /local/compute/{id}/result
	path := strings.TrimPrefix(r.URL.Path, "/local/compute/")
	parts := strings.SplitN(path, "/", 2)

	if len(parts) == 2 && parts[1] == "result" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		api.submitTaskResult(w, r, parts[0])
		return
	}

	writeError(w, http.StatusNotFound, "not found")
}

func (api *LocalAPI) submitTaskResult(w http.ResponseWriter, r *http.Request, taskID string) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req struct {
		ResultID string `json:"result_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.ResultID == "" {
		writeError(w, http.StatusBadRequest, "result_id required")
		return
	}

	if err := api.node.SubmitTaskResult(taskID, req.ResultID); err != nil {
		writeError(w, http.StatusInternalServerError, "submit result failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "completed", "task_id": taskID})
}

// handleAwareness handles awareness snapshot store/retrieve.
// POST /local/awareness       -> Store awareness snapshot
// GET  /local/awareness?id=X  -> Retrieve awareness snapshot
func (api *LocalAPI) handleAwareness(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		api.storeAwareness(w, r)
	case http.MethodGet:
		api.getAwareness(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (api *LocalAPI) storeAwareness(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}

	// Extract ID from the JSON body.
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	id, ok := parsed["id"].(string)
	if !ok || id == "" {
		writeError(w, http.StatusBadRequest, "id field required in body")
		return
	}

	key := PrefixKey("awareness", id)
	if err := api.node.Store(key, body); err != nil {
		writeError(w, http.StatusInternalServerError, "store awareness failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "stored", "id": id})
}

func (api *LocalAPI) getAwareness(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id parameter required")
		return
	}

	key := PrefixKey("awareness", id)
	data, err := api.node.FindValue(key)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "find awareness failed: "+err.Error())
		return
	}
	if data == nil {
		writeError(w, http.StatusNotFound, "awareness snapshot not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// fileUploadRequest is the JSON body for POST /local/files.
type fileUploadRequest struct {
	FileID       string `json:"file_id"`
	FileName     string `json:"file_name"`
	FileSize     int64  `json:"file_size"`
	Cipher       string `json:"cipher"`
	Salt         string `json:"salt"`          // base64
	Nonce        string `json:"nonce"`         // base64
	Ciphertext   string `json:"ciphertext"`    // base64
	DataShards   int    `json:"data_shards"`
	ParityShards int    `json:"parity_shards"`
	OperatorID   string `json:"operator_id"`
}

// handleFiles handles file listing and upload.
// POST /local/files       -> DistributeFile
// GET  /local/files?operator_id=X -> GetFileIndex
func (api *LocalAPI) handleFiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		api.uploadFile(w, r)
	case http.MethodGet:
		api.listFiles(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (api *LocalAPI) uploadFile(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req fileUploadRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.FileID == "" {
		writeError(w, http.StatusBadRequest, "file_id required")
		return
	}

	if req.DataShards <= 0 || req.ParityShards <= 0 {
		writeError(w, http.StatusBadRequest, "data_shards and parity_shards must be positive")
		return
	}

	salt, err := base64.StdEncoding.DecodeString(req.Salt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 salt: "+err.Error())
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 nonce: "+err.Error())
		return
	}
	ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 ciphertext: "+err.Error())
		return
	}

	manifest, err := api.node.DistributeFile(DistributeFileParams{
		FileID:       req.FileID,
		FileName:     req.FileName,
		FileSize:     req.FileSize,
		Cipher:       req.Cipher,
		Salt:         salt,
		Nonce:        nonce,
		Ciphertext:   ciphertext,
		DataShards:   req.DataShards,
		ParityShards: req.ParityShards,
		OperatorID:   req.OperatorID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "distribute file failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, manifest)
}

func (api *LocalAPI) listFiles(w http.ResponseWriter, r *http.Request) {
	operatorID := r.URL.Query().Get("operator_id")
	if operatorID == "" {
		writeError(w, http.StatusBadRequest, "operator_id parameter required")
		return
	}

	index, err := api.node.GetFileIndex(operatorID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get file index failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, index)
}

// handleFilesByID handles file operations by ID.
// GET    /local/files/{id}       -> RetrieveManifest
// GET    /local/files/{id}/data  -> ReconstructFile
// DELETE /local/files/{id}?operator_id=X -> DeleteDistributedFile
func (api *LocalAPI) handleFilesByID(w http.ResponseWriter, r *http.Request) {
	// Parse: /local/files/{id} or /local/files/{id}/data
	path := strings.TrimPrefix(r.URL.Path, "/local/files/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "file ID required in path")
		return
	}

	parts := strings.SplitN(path, "/", 2)
	fileID := parts[0]

	// Check if this is a /data sub-resource request.
	if len(parts) == 2 && parts[1] == "data" {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		api.downloadFileData(w, r, fileID)
		return
	}

	switch r.Method {
	case http.MethodGet:
		api.getFileManifest(w, r, fileID)
	case http.MethodDelete:
		api.deleteFile(w, r, fileID)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (api *LocalAPI) getFileManifest(w http.ResponseWriter, _ *http.Request, fileID string) {
	manifest, err := api.node.RetrieveManifest(fileID)
	if err != nil {
		if errors.Is(err, ErrManifestNotFound) {
			writeError(w, http.StatusNotFound, "manifest not found")
		} else {
			writeError(w, http.StatusInternalServerError, "retrieve manifest: "+err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, manifest)
}

func (api *LocalAPI) downloadFileData(w http.ResponseWriter, _ *http.Request, fileID string) {
	data, err := api.node.ReconstructFile(fileID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reconstruct file failed: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (api *LocalAPI) deleteFile(w http.ResponseWriter, r *http.Request, fileID string) {
	operatorID := r.URL.Query().Get("operator_id")
	if operatorID == "" {
		writeError(w, http.StatusBadRequest, "operator_id parameter required")
		return
	}

	if err := api.node.DeleteDistributedFile(fileID, operatorID); err != nil {
		writeError(w, http.StatusInternalServerError, "delete file failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "file_id": fileID})
}

// handleMessageSend handles POST /local/messages/send.
// Body: {"to": "hex-node-id", "content": {...}}
func (api *LocalAPI) handleMessageSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req struct {
		To      string          `json:"to"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.To == "" {
		writeError(w, http.StatusBadRequest, "to field required")
		return
	}
	if req.Content == nil {
		writeError(w, http.StatusBadRequest, "content field required")
		return
	}

	toBytes, err := hex.DecodeString(req.To)
	if err != nil || len(toBytes) != IDLength {
		writeError(w, http.StatusBadRequest, "invalid to: must be 64-char hex node ID")
		return
	}
	var toID NodeID
	copy(toID[:], toBytes)

	if err := api.node.SendDirectMessage(toID, req.Content); err != nil {
		writeError(w, http.StatusInternalServerError, "send message failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// handleMessageInbox handles GET /local/messages/inbox.
func (api *LocalAPI) handleMessageInbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	messages, err := api.node.CheckInbox()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "check inbox failed: "+err.Error())
		return
	}

	if messages == nil {
		messages = []DirectPayload{}
	}
	writeJSON(w, http.StatusOK, messages)
}

// handleMessageInboxByNonce handles DELETE /local/messages/inbox/{nonce}.
func (api *LocalAPI) handleMessageInboxByNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	nonce := strings.TrimPrefix(r.URL.Path, "/local/messages/inbox/")
	if nonce == "" {
		writeError(w, http.StatusBadRequest, "nonce required in path")
		return
	}

	// Clear the inbox entry for this node.
	inboxKey := PrefixKey("inbox", api.node.ID().Hex())
	if err := api.node.store.Delete(inboxKey); err != nil {
		writeError(w, http.StatusInternalServerError, "delete inbox message failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "nonce": nonce})
}
