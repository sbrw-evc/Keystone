package policy

import (
	"encoding/base64"
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"
)

func argon2PHC(password string, m, t uint32, p uint8, pad bool) string {
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(password), salt, t, m, p, 32)
	enc := base64.RawStdEncoding
	if pad {
		enc = base64.StdEncoding
	}
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, t, p, enc.EncodeToString(salt), enc.EncodeToString(key))
}

func TestHashFormats(t *testing.T) {
	h := argon2PHC("Secret-1", 65536, 3, 4, false)
	if !ValidHash(h) || !CheckPassword(h, "Secret-1") || CheckPassword(h, "Secret-2") || !NeedsRehash(h) {
		t.Fatalf("argon2id %s", h)
	}
	if p := argon2PHC("Secret-1", 1024, 1, 1, true); !CheckPassword(p, "Secret-1") {
		t.Fatal("argon2id with padding")
	}
	own, _ := HashPassword("Secret-1")
	if !ValidHash(own) || NeedsRehash(own) || !CheckPassword(own, "Secret-1") {
		t.Fatal("pbkdf2")
	}
	for _, bad := range []string{"", "plain", "$argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=1048576,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", "$argon2id$v=19$m=65536,t=11,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", "$argon2id$v=19$m=65536,t=3$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"pbkdf2-sha256$10$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", "pbkdf2-sha256$600000$c2E$aGFzaGhhc2hoYXNoaGFzaA"} {
		if ValidHash(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}
