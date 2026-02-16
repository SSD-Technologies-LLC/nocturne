package mesh

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ssd-technologies/nocturne/internal/ratelimit"
)

// WSMessage is the JSON message format for WebSocket communication.
type WSMessage struct {
	Type    string          `json:"type"`    // "register", "heartbeat", "disconnect", "store_shard", "fetch_shard"
	Payload json.RawMessage `json:"payload"`
}

// WSResponse is a JSON response sent back to the client.
type WSResponse struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// RegisterPayload is the payload for a "register" message.
type RegisterPayload struct {
	ID          string `json:"id"`
	Address     string `json:"address"`
	PublicKey   []byte `json:"public_key"`
	ShardSecret []byte `json:"shard_secret"`
	MaxStorage  int64  `json:"max_storage"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// HandleWebSocket returns an HTTP handler that upgrades connections to WebSocket
// and processes mesh node messages.
func HandleWebSocket(tracker *Tracker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("websocket upgrade error: %v", err)
			return
		}
		defer conn.Close()

		limiter := ratelimit.New(60, time.Minute)
		var nodeID string

		defer func() {
			if nodeID != "" {
				tracker.Unregister(nodeID)
			}
		}()

		for {
			var msg WSMessage
			if err := conn.ReadJSON(&msg); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					log.Printf("websocket read error: %v", err)
				}
				return
			}

			if !limiter.Allow() {
				writeError(conn, "rate limit exceeded")
				continue
			}

			switch msg.Type {
			case "register":
				var payload RegisterPayload
				if err := json.Unmarshal(msg.Payload, &payload); err != nil {
					writeError(conn, "invalid register payload")
					continue
				}
				node := &NodeInfo{
					ID:          payload.ID,
					Address:     payload.Address,
					PublicKey:   payload.PublicKey,
					ShardSecret: payload.ShardSecret,
					MaxStorage:  payload.MaxStorage,
				}
				tracker.Register(node)
				nodeID = payload.ID
				resp := WSResponse{
					Type:    "registered",
					Payload: map[string]string{"node_id": payload.ID},
				}
				if err := conn.WriteJSON(resp); err != nil {
					log.Printf("websocket write error: %v", err)
					return
				}

			case "heartbeat":
				if nodeID != "" {
					tracker.Heartbeat(nodeID)
				}
				resp := WSResponse{
					Type:    "heartbeat_ack",
					Payload: map[string]string{"status": "ok"},
				}
				if err := conn.WriteJSON(resp); err != nil {
					log.Printf("websocket write error: %v", err)
					return
				}

			case "disconnect":
				if nodeID != "" {
					tracker.Unregister(nodeID)
					nodeID = "" // prevent double-unregister in defer
				}
				resp := WSResponse{
					Type:    "disconnected",
					Payload: map[string]string{"status": "ok"},
				}
				_ = conn.WriteJSON(resp)
				return

			default:
				writeError(conn, "unknown message type: "+msg.Type)
			}
		}
	}
}

func writeError(conn *websocket.Conn, message string) {
	resp := WSResponse{
		Type:    "error",
		Payload: map[string]string{"error": message},
	}
	_ = conn.WriteJSON(resp)
}
