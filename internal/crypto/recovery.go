package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// 256 curated words — dark/tech/security theme
var wordlist = []string{
	// 0-23
	"shadow", "cipher", "vault", "ember", "frost", "onyx",
	"pulse", "storm", "nexus", "drift", "blade", "forge",
	"echo", "raven", "orbit", "crest", "shard", "flare",
	"glyph", "thorn", "viper", "delta", "wraith", "nova",
	// 24-47
	"prism", "surge", "helix", "blaze", "talon", "aegis",
	"flux", "abyss", "zenith", "cobalt", "phantom", "dusk",
	"iron", "spark", "tide", "apex", "rune", "obsidian",
	"lunar", "bolt", "veil", "arc", "pyre", "mirage",
	// 48-71
	"sigil", "aurora", "tempest", "crimson", "void", "oracle",
	"basalt", "spectre", "titan", "nether", "axion", "quartz",
	"raptor", "fathom", "vector", "mantis", "pyrite", "scarab",
	"vertex", "warden", "nebula", "carbon", "dynamo", "ether",
	// 72-95
	"granite", "hydra", "ivory", "jackal", "krypton", "lancer",
	"magnet", "nitro", "omega", "paladin", "quasar", "reflex",
	"silicon", "turret", "umbra", "vulcan", "xenon", "yarrow",
	"zephyr", "amber", "bronze", "chrome", "device", "enigma",
	// 96-119
	"falcon", "garnet", "harbor", "indigo", "jasper", "karma",
	"lithium", "matrix", "neptune", "optic", "plasma", "quantum",
	"reactor", "stealth", "thorium", "ultra", "valiant", "wolfram",
	"anchor", "beacon", "cascade", "daemon", "eclipse", "furnace",
	// 120-143
	"glacier", "horizon", "impulse", "javelin", "keystone", "lattice",
	"mithril", "nucleus", "oxide", "phoenix", "radiant", "sentinel",
	"trident", "uranium", "venture", "wyvern", "alloy", "binary",
	"conduit", "dagger", "element", "fractal", "gallium", "helios",
	// 144-167
	"inferno", "junction", "kinetic", "legacy", "monolith", "neutron",
	"obelisk", "pinnacle", "quiver", "ripple", "solar", "tungsten",
	"unison", "voltage", "whisper", "argon", "bastion", "catalyst",
	"diode", "entropy", "fulcrum", "gamma", "harpoon", "iridium",
	// 168-191
	"jolt", "kestrel", "lumen", "meridian", "noctis", "osmium",
	"paradox", "resonance", "stratum", "tundra", "utopia", "vortex",
	"atlas", "borealis", "cortex", "draco", "epoch", "fiber",
	"golem", "haven", "icon", "klaxon", "lever", "morph",
	// 192-215
	"nadir", "piston", "quarry", "ridge", "strix", "torque",
	"anvil", "breach", "comet", "equinox", "flint", "grail",
	"iris", "jester", "kraken", "lynx", "mantle", "nomad",
	"outpost", "prowl", "quest", "radon", "slate", "trace",
	// 216-239
	"usher", "valve", "wrench", "arrow", "crow", "dune",
	"smelt", "grim", "haze", "ink", "jet", "knot",
	"loom", "mist", "null", "oath", "peak", "quell",
	"rust", "silk", "tusk", "urn", "wane", "yoke",
	// 240-255
	"zinc", "bane", "clad", "dirk", "fang", "glint",
	"helm", "jade", "kite", "latch", "mace", "nook",
	"orb", "plume", "raze", "scythe",
}

func GenerateRecoveryKey() (hexKey string, mnemonic string, err error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", "", fmt.Errorf("generate entropy: %w", err)
	}

	hexKey = hex.EncodeToString(entropy)

	// 6-word mnemonic from first 6 bytes
	words := make([]string, 6)
	for i := 0; i < 6; i++ {
		words[i] = wordlist[int(entropy[i])%len(wordlist)]
	}
	mnemonic = strings.Join(words, " ")

	return hexKey, mnemonic, nil
}

type escrowData struct {
	Password string `json:"p"`
	Salt     []byte `json:"s"`
}

func CreateEscrow(hexKey, password string, salt []byte) ([]byte, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode hex key: %w", err)
	}

	data, err := json.Marshal(escrowData{Password: password, Salt: salt})
	if err != nil {
		return nil, fmt.Errorf("marshal escrow: %w", err)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

func RecoverFromEscrow(hexKey string, escrowBlob []byte) (password string, salt []byte, err error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", nil, fmt.Errorf("decode hex key: %w", err)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, fmt.Errorf("new gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(escrowBlob) < nonceSize {
		return "", nil, fmt.Errorf("escrow data too short")
	}

	nonce := escrowBlob[:nonceSize]
	ciphertext := escrowBlob[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", nil, fmt.Errorf("decrypt escrow: %w", err)
	}

	var data escrowData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return "", nil, fmt.Errorf("unmarshal escrow: %w", err)
	}

	return data.Password, data.Salt, nil
}
