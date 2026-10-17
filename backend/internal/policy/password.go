package policy

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

var Iterations = 600_000

const saltLen = 16

// HashPassword makes Keystone's own hash: pbkdf2-sha256$<iterations>$<salt>$<key> (base64 without padding).
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, Iterations, 32)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", Iterations, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

var dummyHash, _ = HashPassword("spa-dummy-password")

// b64 decodes base64 of the standard alphabet with or without padding.
func b64(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

// pbkdf2Hash is a parsed pbkdf2-sha256 hash.
type pbkdf2Hash struct {
	iter      int
	salt, key []byte
}

func parsePBKDF2(hash string) (pbkdf2Hash, bool) {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return pbkdf2Hash{}, false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1000 || iter > 10_000_000 {
		return pbkdf2Hash{}, false
	}
	salt, err1 := b64(parts[2])
	key, err2 := b64(parts[3])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(key) < 16 || len(key) > 64 {
		return pbkdf2Hash{}, false
	}
	return pbkdf2Hash{iter, salt, key}, true
}

// argon2Hash is a parsed Argon2id hash in the PHC string format: $argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>.
type argon2Hash struct {
	memory     uint32
	time       uint32
	threads    uint8
	salt, hash []byte
}

func parseArgon2id(hash string) (argon2Hash, bool) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return argon2Hash{}, false
	}
	var h argon2Hash
	seen := 0
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 10, 32)
		if !ok || err != nil {
			return argon2Hash{}, false
		}
		switch k {
		case "m":
			h.memory, seen = uint32(n), seen|1
		case "t":
			h.time, seen = uint32(n), seen|2
		case "p":
			if n > 255 {
				return argon2Hash{}, false
			}
			h.threads, seen = uint8(n), seen|4
		default:
			return argon2Hash{}, false
		}
	}
	if seen != 7 || h.threads < 1 || h.threads > 16 || h.time < 1 || h.time > 10 ||
		h.memory < 8*uint32(h.threads) || h.memory > 262144 {
		return argon2Hash{}, false
	}
	var err1, err2 error
	h.salt, err1 = b64(parts[4])
	h.hash, err2 = b64(parts[5])
	if err1 != nil || err2 != nil || len(h.salt) < 8 || len(h.hash) < 16 || len(h.hash) > 64 {
		return argon2Hash{}, false
	}
	return h, true
}

// ValidHash tells whether Keystone can check passwords against hash: pbkdf2-sha256 (its own) or Argon2id (PHC),
// with parameters in the accepted ranges (docs/protocol.md, users/import).
func ValidHash(hash string) bool {
	if _, ok := parsePBKDF2(hash); ok {
		return true
	}
	_, ok := parseArgon2id(hash)
	return ok
}

// NeedsRehash: the hash is not Keystone's current one (Argon2id from an application, or fewer iterations), so after a
// successful check it is replaced with a new HashPassword.
func NeedsRehash(hash string) bool {
	p, ok := parsePBKDF2(hash)
	return !ok || p.iter != Iterations
}

// CheckPassword checks password against a pbkdf2-sha256 or Argon2id hash. An empty hash takes the time of a real
// check and fails.
func CheckPassword(hash, password string) bool {
	if hash == "" {
		hash = dummyHash
		password += "\x00"
	}
	if p, ok := parsePBKDF2(hash); ok {
		got, err := pbkdf2.Key(sha256.New, password, p.salt, p.iter, len(p.key))
		return err == nil && subtle.ConstantTimeCompare(got, p.key) == 1
	}
	if h, ok := parseArgon2id(hash); ok {
		got := argon2.IDKey([]byte(password), h.salt, h.time, h.memory, h.threads, uint32(len(h.hash)))
		return subtle.ConstantTimeCompare(got, h.hash) == 1
	}
	return false
}

func RandomToken(prefix string, bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}
func TokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
